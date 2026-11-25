"""The AgentCore service wrapper around the containment kernel.

Two paths share one kernel:

``ask``
    The production path. Bedrock Converse proposes tool calls. Every proposed
    call is executed through :class:`hold.kernel.AuthorityKernel`, which can
    refuse it. The model never receives a credential and never gets to write
    state directly.

``turn``
    The deterministic path used by the public demo and the stress suite. It is
    intentionally not a fake model: it is a scripted set of the same real tool
    calls, so the receipts and ledger are genuine.

The service is deliberately small. It is not the safety boundary; if every line
in this file were replaced by an attacker, the kernel would still refuse a
release, a scope reduction, a deletion or an export.
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any, Mapping, Sequence

from hold.cosign import CosignAuthority
from hold.domain import AGENT, SYSTEM, Channel, Decision, Trust
from hold.engine import BedrockConverseAgent, Session, Turn
from hold.guardrail import InputGuard
from hold.kernel import AuthorityKernel
from hold.ledger import Ledger
from hold.scenario import route
from hold.seed import build_world
from hold.taint import Provenance
from hold.util import iso

from .prompt import prompt_for

DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-20250514-v1:0"


def _load_cosign_key() -> bytes:
    """Load the human-plane signing key from the deployment environment.

    There is deliberately no built-in default. A public fallback key would let
    anyone holding the repository mint a co-signature, which defeats the entire
    two-person rule. The runtime refuses to start without a configured key.
    """
    value = os.environ.get("HOLD_COSIGN_KEY")
    if value:
        return value.encode("utf-8")

    secret_arn = os.environ.get("HOLD_COSIGN_KEY_SECRET_ARN")
    if secret_arn:
        try:
            import boto3  # type: ignore
        except ModuleNotFoundError as exc:  # pragma: no cover - deployment dependency
            raise RuntimeError(
                "HOLD_COSIGN_KEY_SECRET_ARN is set but boto3 is not installed."
            ) from exc
        client = boto3.client(
            "secretsmanager",
            region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        )
        payload = client.get_secret_value(SecretId=secret_arn)
        secret = payload.get("SecretString") or ""
        if not secret:
            raise RuntimeError(
                f"Secrets Manager secret {secret_arn!r} is empty; refusing to start."
            )
        return secret.encode("utf-8")

    raise RuntimeError(
        "No human-plane co-signature key is configured. Set HOLD_COSIGN_KEY or "
        "HOLD_COSIGN_KEY_SECRET_ARN before starting the containment runtime."
    )


class HoldService:
    """One incident, one kernel, one hash-chained ledger."""

    def __init__(
        self,
        *,
        model_id: str | None = None,
        region: str | None = None,
        guardrail_id: str | None = None,
        guardrail_version: str | None = None,
        cosign_key: bytes | None = None,
        notify_rate_per_minute: int | None = None,
    ) -> None:
        self.lock = threading.RLock()
        self.run_id = uuid.uuid4().hex[:8]
        self.world = build_world()
        self.guard = InputGuard()
        self.cosign = CosignAuthority(cosign_key or _load_cosign_key())
        self.ledger = Ledger()
        self.kernel = AuthorityKernel(
            self.world,
            self.ledger,
            self.cosign,
            notify_rate_per_minute=notify_rate_per_minute
            or int(os.environ.get("HOLD_NOTIFY_RATE", "4")),
        )
        self.session = Session(
            self.world, self.kernel, self.guard, self.ledger, router=route
        )
        self.model_id = model_id or os.environ.get("HOLD_MODEL_ID", DEFAULT_MODEL)
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self.guardrail_id = guardrail_id or os.environ.get("HOLD_GUARDRAIL_ID")
        self.guardrail_version = guardrail_version or os.environ.get(
            "HOLD_GUARDRAIL_VERSION", "DRAFT"
        )
        self.agent = BedrockConverseAgent(
            model_id=self.model_id,
            region=self.region,
            guardrail_id=self.guardrail_id,
            guardrail_version=self.guardrail_version,
            system_prompt=prompt_for(self.world.incident_id),
        )

    # -- shared helpers ---------------------------------------------------

    def _invoke(
        self,
        tool: str,
        args: Mapping[str, Any],
        provenance: Sequence[Provenance] = (),
    ) -> tuple[Any, dict[str, Any]]:
        """Run one tool call and return (result, model-facing payload)."""
        result = self.kernel.invoke(AGENT, tool, dict(args), provenance=tuple(provenance))
        payload = result.to_json()
        if tool == "read_supplier_doc" and result.decision is Decision.ALLOW:
            info = self.session.ingest_document(str(args.get("doc_id", "")))
            if info:
                # The model sees the quarantine-wrapped text, never the raw body.
                payload["output"] = {
                    **dict(payload.get("output") or {}),
                    "content": info["model_text"],
                }
                payload["provenance"] = [info["provenance"]]
                payload["scan"] = info["scan"]
        return result, payload

    def _ledger_summary(self) -> dict[str, Any]:
        status = self.ledger.verify().to_json()
        return {**status, "head": self.ledger.head}

    def _base(self, prompt: str, guard: Any, mode: str) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "user": prompt,
            "actor": AGENT.to_json(),
            "mode": mode,
            "model_id": self.model_id,
            "guard": guard.to_json(),
            "results": [],
            "final": "",
            "state": self.kernel.state.summary(),
            "at": iso(),
            "flags": [],
            "provenance": [],
            "ledger": self._ledger_summary(),
        }

    # -- production path --------------------------------------------------

    def ask(self, prompt: str) -> dict[str, Any]:
        """Screen the prompt, run Bedrock Converse, and contain every tool call."""
        if not isinstance(prompt, str) or not prompt.strip():
            return {"error": "prompt must be a non-empty string"}

        with self.lock:
            guard = self.guard.screen(prompt)
            if guard.blocked:
                turn = self.session.turn(prompt, mode="LIVE_BEDROCK")
                data = turn.to_json()
                data["run_id"] = self.run_id
                data["model_id"] = self.model_id
                data["ledger"] = self._ledger_summary()
                return data

            try:
                return self._ask_model(prompt, guard)
            except Exception as exc:  # noqa: BLE001 - do not leak credentials in errors
                data = self._base(prompt, guard, "LIVE_BEDROCK_ERROR")
                data["final"] = (
                    "The model call failed before a reply could be composed. "
                    "No containment state was changed by this request. Check the "
                    "runtime logs; the ledger remains the source of truth."
                )
                data["flags"] = ["MODEL_ERROR"]
                data["error"] = type(exc).__name__
                data["ledger"] = self._ledger_summary()
                return data

    def _ask_model(self, prompt: str, guard: Any) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": [{"text": guard.text}]}
        ]
        results: list[Any] = []
        provenance: list[Provenance] = []
        texts: list[str] = []
        flags: list[str] = list(guard.signals)

        for _ in range(8):
            response = self.agent.converse(messages)
            message = (response.get("output") or {}).get("message") or {}
            content = list(message.get("content") or [])
            if not content:
                break
            messages.append({"role": "assistant", "content": content})

            tool_uses = []
            for block in content:
                if "text" in block:
                    texts.append(str(block["text"]))
                elif "toolUse" in block:
                    tool_uses.append(block["toolUse"])
            if not tool_uses:
                break

            tool_results = []
            for use in tool_uses:
                name = str(use.get("name", ""))
                args = dict(use.get("input") or {})
                result, payload = self._invoke(name, args, provenance)
                results.append(result)
                if name == "read_supplier_doc" and result.decision is Decision.ALLOW:
                    info = self.session.taint.get(str(args.get("doc_id", "")))
                    if info:
                        provenance.append(
                            Provenance(
                                source_id=info.provenance.source_id,
                                channel=Channel(info.provenance.channel),
                                trust=Trust(info.provenance.trust),
                                label=info.provenance.label,
                            )
                        )
                        if info.scan.suspected:
                            flags.append("INJECTION_SUSPECTED")
                tool_results.append(
                    {
                        "toolResult": {
                            "toolUseId": use.get("toolUseId", ""),
                            "content": [{"json": payload}],
                            "status": "success",
                        }
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        text = "\n".join(t.strip() for t in texts if t and t.strip()).strip()
        if not text:
            text = (
                "I completed the tool calls, but I could not compose a usable reply. "
                "The receipts are in the ledger; ask me for containment status."
            )
            flags.append("EMPTY_MODEL_REPLY")

        out = self.guard.screen_output(text)
        if out.blocked:
            self.kernel.invoke(
                SYSTEM,
                "escalate_incident",
                {
                    "reason_code": "DATA_INTEGRITY",
                    "note": "Output guardrail blocked a draft reply from the live model.",
                },
            )
            text = (
                "I drafted something the output guardrail refused to release. "
                "That is a defect in my response, not a decision about the product. "
                "I have escalated it to a human."
            )
            flags.append("OUTPUT_GUARDRAIL_BLOCK")
        else:
            text = out.text

        leaked, doc_id = self.session.taint.leak_check(text)
        if leaked:
            text = self.session.taint.strip_canaries(text)
            flags.append("CANARY_ECHO_STRIPPED")
            self.ledger.append(
                {
                    "tenant": self.world.tenant_id,
                    "incident": self.world.incident_id,
                    "tool": "__output__",
                    "effect": "READ",
                    "actor": AGENT.to_json(),
                    "decision": "ALLOW",
                    "code": "CANARY_ECHO",
                    "layer": "PROVENANCE",
                    "args": {"doc_id": doc_id},
                    "args_digest": "",
                    "provenance": [],
                    "flags": ["CANARY_ECHO_STRIPPED"],
                    "attempted_loosening": False,
                    "state_before": self.kernel.state.digest(),
                    "state_after": self.kernel.state.digest(),
                    "delta": {},
                    "cosign": None,
                }
            )

        data = self._base(prompt, guard, "LIVE_BEDROCK")
        data.update(
            {
                "results": [r.to_json() for r in results],
                "final": text,
                "state": self.kernel.state.summary(),
                "flags": sorted(set(flags)),
                "provenance": [p.to_json() for p in provenance],
                "ledger": self._ledger_summary(),
                "output_guard": out.to_json(),
            }
        )
        return data

    # -- deterministic twin (demo and tests) ------------------------------

    def turn(
        self,
        prompt: str,
        *,
        calls: Sequence[Mapping[str, Any]] | None = None,
        final: str | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            turn: Turn = self.session.turn(
                prompt,
                calls=calls,
                final=final,
                mode="LIVE_BEDROCK_REPLAY",
            )
            data = turn.to_json()
            data["run_id"] = self.run_id
            data["model_id"] = self.model_id
            data["ledger"] = self._ledger_summary()
            return data


__all__ = ["HoldService"]
