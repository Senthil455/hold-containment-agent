"""Offline mirror of the Bedrock Guardrail used in front of the agent.

The configuration lives in ``config/guardrail.json`` and is the same object the
CDK stack turns into an ``AWS::Bedrock::Guardrail``. Keeping one file means the
thing we test and the thing we deploy cannot drift.

Scope of the mirror
-------------------
Implemented offline, deterministically:

  * denied topics (legal, medical, safety determination, liability, press)
  * prompt-attack detection (instruction override, role hijack, prompt fishing)
  * PII redaction on the input and output paths
  * size limits

Not reimplemented offline (requires the hosted service):

  * the hate / insults / sexual / violence / misconduct content filters

That gap is stated in the docs and in the UI. The guardrail is also *not* the
safety boundary -- several stress cases are deliberately phrased to pass it, so
that the kernel is the thing being tested.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .util import normalize_text, redact_pii


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "guardrail.json"


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:  # pragma: no cover - packaging fallback
        return {"topicPolicy": {"topicsConfig": []}, "offlineMirror": {}}


# ---------------------------------------------------------------------------
# Topic rules (specific enough not to fire on ordinary containment work)
# ---------------------------------------------------------------------------

_TOPIC_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "LegalAdvice": (
        re.compile(r"\b(liab(le|ility)|lawsuit|sue\b|suing|indemnif\w*|attorney|legal advice|settlement)\b"),
        re.compile(r"\b(does|do|is|are)\b[^.\n]{0,40}\b(fsma|fda|usda|regulation|law)\b[^.\n]{0,30}\b(require|allow|permit|prohibit)\b"),
    ),
    "MedicalAdvice": (
        re.compile(r"\b(pregnan\w*|symptom\w*|diagnos\w*|treatment|doctor|physician|listeriosis|hospitali[sz]ed)\b"),
        re.compile(r"\bis (it|this|the product|the cheese) safe (to eat|for)\b"),
    ),
    "SafetyDetermination": (
        re.compile(r"\b(declare|confirm|certify|determine|mark)\b[^.\n]{0,30}\b(safe|cleared|fit|approved)\b"),
        re.compile(r"\b(narrow|end|close|lift|terminate)\b[^.\n]{0,20}\b(recall|hold|quarantine)\b"),
        re.compile(r"\b(can|could|may) we (release|ship|sell)\b"),
    ),
    "LiabilityNegotiation": (
        re.compile(r"\b(compensat\w*|settlement|damages|pay (them|the customer)|credit memo|goodwill credit)\b"),
    ),
    "PressComment": (
        re.compile(r"\b(press|tweet|social media|reporter|journalist|news outlet|media statement|public statement)\b"),
    ),
}

# Prompt-attack signals. Weighted; threshold from config.
_ATTACK_PATTERNS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    ("instruction_override", 3, re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,45}"
        r"\b(previous|prior|above|earlier|all|your)\b[^.\n]{0,20}"
        r"\b(instruction|rule|prompt|direction|polic(y|ies)|guideline)s?\b")),
    ("role_hijack", 2, re.compile(
        r"\b(you are now|from now on you|act as|pretend to be|roleplay as|developer mode|jailbreak|do anything now)\b")),
    ("system_spoof", 2, re.compile(r"(<\|\s*system\s*\|>)|(\bsystem\s*:)|(\[/?INST\])|(###\s*instruction)|(\bbegin system\b)")),
    ("prompt_fishing", 3, re.compile(
        r"\b(reveal|print|repeat|show|dump|output)\b[^.\n]{0,30}"
        r"\b(system prompt|instructions|configuration|guardrail|policy text)\b")),
    ("no_rules", 2, re.compile(r"\b(no restrictions|without restrictions|unfiltered|uncensored|any rules)\b")),
    ("encoded_payload", 1, re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")),
    ("tool_smuggling", 2, re.compile(r"\b(tool_call|function_call|<function|invoke_tool)\b")),
)


@dataclass(frozen=True, slots=True)
class GuardResult:
    action: str           # ALLOW | BLOCK | REDACT
    code: str
    layer: str
    reason: str
    topics: tuple[str, ...] = ()
    attack_score: int = 0
    signals: tuple[str, ...] = ()
    text: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == "BLOCK"

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "code": self.code,
            "layer": self.layer,
            "reason": self.reason,
            "topics": list(self.topics),
            "attack_score": self.attack_score,
            "signals": list(self.signals),
        }


class InputGuard:
    """Deterministic input screening, evaluated before the model is called."""

    def __init__(self) -> None:
        cfg = load_config()
        mirror = cfg.get("offlineMirror", {})
        self.threshold = int(mirror.get("promptAttackThreshold", 2))
        self.max_chars = int(mirror.get("maxInputChars", 6000))

    def screen(self, text: str) -> GuardResult:
        if len(text) > self.max_chars:
            return GuardResult(
                "BLOCK", "INPUT_TOO_LARGE", "GUARDRAIL",
                f"Input exceeds {self.max_chars} characters. Split the request.", text=text,
            )

        norm = normalize_text(text)

        topics = tuple(
            name for name, patterns in _TOPIC_PATTERNS.items()
            if any(p.search(norm) for p in patterns)
        )
        if topics:
            pretty = ", ".join(t.replace("Advice", " advice").replace("Determination", " determination")
                               for t in topics)
            return GuardResult(
                "BLOCK", "DENIED_TOPIC", "GUARDRAIL",
                f"This request asks for {pretty}, which the containment agent is not "
                "permitted to provide. It has been routed to a qualified human.",
                topics=topics, text=text,
            )

        score = 0
        signals: list[str] = []
        for name, weight, pattern in _ATTACK_PATTERNS:
            if pattern.search(norm):
                score += weight
                signals.append(name)
        if score >= self.threshold:
            return GuardResult(
                "BLOCK", "PROMPT_ATTACK", "GUARDRAIL",
                "The request contains prompt-attack signals and was stopped before "
                "the model saw it. The attempt is recorded in the ledger.",
                attack_score=score, signals=tuple(signals), text=text,
            )

        redacted = redact_pii(text)
        if redacted != text:
            return GuardResult(
                "REDACT", "PII_REDACTED", "GUARDRAIL",
                "Contact data was masked before the prompt was assembled.",
                attack_score=score, signals=tuple(signals), text=redacted,
            )

        return GuardResult("ALLOW", "OK", "GUARDRAIL", "Input passed.", text=text)

    # -- output -----------------------------------------------------------

    def screen_output(self, text: str) -> GuardResult:
        """Output-side checks.

        Grounding is enforced by the hosted guardrail against retrieved passages.
        Locally we enforce the two things that are deterministic: PII masking and
        a small set of prohibited determination phrases.
        """
        banned = re.compile(
            r"\b(this|the) (product|lot|cheese|food) is (safe|fit for (sale|consumption)|cleared)\b",
            re.IGNORECASE,
        )
        if banned.search(text):
            return GuardResult(
                "BLOCK", "UNGROUNDED_DETERMINATION", "GUARDRAIL",
                "The draft made a safety determination that the agent has no authority "
                "to make. Blocked from release to the operator.",
                text=text,
            )
        redacted = redact_pii(text)
        leaked, doc = False, ""
        if redacted != text:
            return GuardResult(
                "REDACT", "OUTPUT_PII_MASKED", "GUARDRAIL",
                "Contact data was masked in the agent's response.", text=redacted,
            )
        return GuardResult("ALLOW", "OK", "GUARDRAIL", "Output passed.", text=text)


def topic_catalogue() -> list[dict[str, Any]]:
    cfg = load_config()
    return list(cfg.get("topicPolicy", {}).get("topicsConfig", []))


def guardrail_summary() -> dict[str, Any]:
    cfg = load_config()
    return {
        "name": cfg.get("name", "hold-containment-guardrail"),
        "version": cfg.get("version", "0"),
        "topics": [t["name"] for t in topic_catalogue()],
        "promptAttackThreshold": int(
            cfg.get("offlineMirror", {}).get("promptAttackThreshold", 2)
        ),
        "hostedOnly": [
            "HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT",
            "contextual grounding (GROUNDING/RELEVANCE)",
        ],
    }


__all__ = [
    "InputGuard",
    "GuardResult",
    "load_config",
    "topic_catalogue",
    "guardrail_summary",
]
