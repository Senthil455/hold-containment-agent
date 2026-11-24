"""Conversation engine.

The engine is model-agnostic. It takes a request, runs it through the input
guard, executes the requested tool calls through the kernel, and composes a
reply. In `live` mode the tool calls come from Amazon Bedrock Converse tool-use.
In `replay` mode they come from an authored script, and in `router` mode from a
small deterministic intent router.

Why a deterministic router exists at all: the demo has to run from a clean
checkout with no AWS account. Pretending a canned script is a language model
would be dishonest, so the modes are labelled in the UI and the harness treats
the model as *fully compromised* when it runs the stress suite. The claim being
tested is not "the model refuses"; it is "the boundary holds even when the model
does not."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from .domain import (
    AGENT,
    SYSTEM,
    Actor,
    Channel,
    ContainmentState,
    InvocationResult,
    Trust,
    World,
)
from .guardrail import GuardResult, InputGuard
from .kernel import AuthorityKernel
from .ledger import Ledger
from .taint import Provenance, TaintBroker
from .util import clip, iso, redact_pii


@dataclass(slots=True)
class Turn:
    user: str
    actor: Actor
    mode: str
    guard: GuardResult
    results: list[InvocationResult]
    final: str
    state: ContainmentState
    at: str
    flags: list[str] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)

    def by_tool(self, name: str) -> list[InvocationResult]:
        return [r for r in self.results if r.tool == name]

    def first(self, name: str) -> InvocationResult | None:
        items = self.by_tool(name)
        return items[0] if items else None

    @property
    def denied(self) -> list[InvocationResult]:
        return [r for r in self.results if r.blocked]

    def to_json(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "actor": self.actor.to_json(),
            "mode": self.mode,
            "guard": self.guard.to_json(),
            "results": [r.to_json() for r in self.results],
            "final": self.final,
            "state": self.state.summary(),
            "at": self.at,
            "flags": self.flags,
            "provenance": [p.to_json() for p in self.provenance],
        }


class Session:
    def __init__(
        self,
        world: World,
        kernel: AuthorityKernel,
        guard: InputGuard,
        ledger: Ledger,
        *,
        router: Callable[[str], list[dict[str, Any]]] | None = None,
    ) -> None:
        self.world = world
        self.kernel = kernel
        self.guard = guard
        self.ledger = ledger
        self.taint = TaintBroker(session_salt=f"{world.tenant_id}:{world.incident_id}")
        self.router = router or (lambda _text: [])
        self.mode = "router"

    # -- documents --------------------------------------------------------

    def ingest_document(self, doc_id: str) -> dict[str, Any] | None:
        doc = self.world.docs.get(doc_id)
        if doc is None:
            return None
        channel = Channel.INTERNAL_QMS if doc.supplier_id == "NORTHFIELD" else (
            Channel.CUSTOMER_EMAIL if doc.kind == "email" else Channel.SUPPLIER_DOC
        )
        tainted = self.taint.ingest(doc, channel)
        if tainted.scan.suspected:
            self.ledger.append(
                {
                    "tenant": self.world.tenant_id,
                    "incident": self.world.incident_id,
                    "tool": "__provenance__",
                    "effect": "READ",
                    "actor": {"id": "system:taint", "kind": "system", "display": "Taint broker", "roles": []},
                    "decision": "ALLOW",
                    "code": "UNTRUSTED_CONTENT_FLAGGED",
                    "layer": "PROVENANCE",
                    "args": {"doc_id": doc_id},
                    "args_digest": tainted.content_sha256,
                    "provenance": [tainted.provenance.to_json()],
                    "flags": ["INJECTION_SUSPECTED", tainted.scan.verdict],
                    "attempted_loosening": False,
                    "state_before": self.kernel.state.digest(),
                    "state_after": self.kernel.state.digest(),
                    "delta": {},
                    "cosign": None,
                    "scan": tainted.scan.to_json(),
                },
                at=iso(),
            )
        return tainted.to_json()

    # -- the turn ---------------------------------------------------------

    def turn(
        self,
        text: str,
        *,
        calls: Sequence[Mapping[str, Any]] | None = None,
        final: str | Callable[["Turn"], str] | None = None,
        actor: Actor = AGENT,
        mode: str | None = None,
        composer: Callable[["Turn"], str] | None = None,
    ) -> Turn:
        mode = mode or self.mode
        guard = self.guard.screen(text)
        at = iso()

        if guard.blocked:
            self.ledger.append(
                {
                    "tenant": self.world.tenant_id,
                    "incident": self.world.incident_id,
                    "tool": "__input__",
                    "effect": "READ",
                    "actor": actor.to_json(),
                    "decision": "DENY",
                    "code": guard.code,
                    "layer": "GUARDRAIL",
                    "args": {"preview": clip(redact_pii(text), 160)},
                    "args_digest": "",
                    "provenance": [],
                    "flags": list(guard.topics) + list(guard.signals),
                    "attempted_loosening": False,
                    "state_before": self.kernel.state.digest(),
                    "state_after": self.kernel.state.digest(),
                    "delta": {},
                    "cosign": None,
                },
                at=at,
            )
            reason = "SUSPECTED_ATTACK" if guard.code == "PROMPT_ATTACK" else "LEGAL_OR_MEDICAL_QUESTION"
            route = self.kernel.invoke(
                SYSTEM,
                "escalate_incident",
                {
                    "reason_code": reason,
                    "note": (
                        f"Guardrail blocked an operator request ({guard.code}). "
                        f"Topics: {', '.join(guard.topics) or 'n/a'}. "
                        f"Signals: {', '.join(guard.signals) or 'n/a'}. "
                        "A qualified human must answer the original question."
                    ),
                },
            )
            results = [route] if not route.blocked else []
            refusal = self._refusal(guard, route)
            return Turn(
                user=text, actor=actor, mode=mode, guard=guard, results=results,
                final=refusal, state=self.kernel.state, at=at,
                flags=["GUARDRAIL_BLOCK", guard.code],
            )

        working_text = guard.text
        provenance: list[Provenance] = []
        results: list[InvocationResult] = []
        flags: list[str] = list(guard.signals)

        plan = list(calls) if calls is not None else list(self.router(working_text))

        for call in plan:
            tool = str(call.get("tool", ""))
            args = dict(call.get("args", {}))
            result = self.kernel.invoke(actor, tool, args, provenance=tuple(provenance))
            results.append(result)

            if tool == "read_supplier_doc" and not result.blocked:
                doc_id = str(args.get("doc_id", ""))
                info = self.ingest_document(doc_id)
                if info:
                    provenance.append(
                        Provenance(
                            source_id=info["provenance"]["source_id"],
                            channel=Channel(info["provenance"]["channel"]),
                            trust=Trust(info["provenance"]["trust"]),
                            label=info["provenance"]["label"],
                        )
                    )
                    if isinstance(result.output, dict):
                        # The model sees the canary-wrapped block, never the raw
                        # document body. This is the live/offline parity point.
                        result.output["content"] = info["model_text"]
                    if info["scan"]["suspected"]:
                        flags.append("INJECTION_SUSPECTED")
        t = Turn(
            user=text,
            actor=actor,
            mode=mode,
            guard=guard,
            results=results,
            final="",
            state=self.kernel.state,
            at=at,
            flags=sorted(set(flags)),
            provenance=provenance,
        )

        composed = ""
        if callable(final):
            composed = final(t)
        elif isinstance(final, str):
            composed = final
        elif composer is not None:
            composed = composer(t)

        out = self.guard.screen_output(composed)
        if out.blocked:
            composed = (
                "I drafted something the output guardrail refused to release. That is a "
                "defect in my response, not a decision about the product. Escalating so a "
                "human can answer directly."
            )
            self.kernel.invoke(
                SYSTEM,
                "escalate_incident",
                {"reason_code": "DATA_INTEGRITY", "note": "Output guardrail blocked a draft reply."},
            )
            flags.append("OUTPUT_GUARDRAIL_BLOCK")
        else:
            composed = out.text

        leaked, doc_id = self.taint.leak_check(composed)
        if leaked:
            composed = self.taint.strip_canaries(composed)
            flags.append("CANARY_ECHO_STRIPPED")
            self.ledger.append(
                {
                    "tenant": self.world.tenant_id,
                    "incident": self.world.incident_id,
                    "tool": "__output__",
                    "effect": "READ",
                    "actor": actor.to_json(),
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
                },
                at=at,
            )

        t.final = composed
        t.flags = sorted(set(flags))
        return t

    # -- refusal text -----------------------------------------------------

    def _refusal(self, guard: GuardResult, route: InvocationResult | None) -> str:
        if guard.code == "DENIED_TOPIC":
            topics = ", ".join(guard.topics).replace("Advice", " advice").replace(
                "Determination", " determination"
            )
            ticket = f" {route.output.get('escalation_id')}" if route and route.output else ""
            return (
                f"I can't help with {topics} — that is outside the containment role, and the "
                "guardrail stopped the request before it reached me. I have opened a human "
                f"review{ticket} for the QA Director, who can answer with the right authority. "
                "What I can do is tell you exactly which lots are affected and what is "
                "currently held."
            )
        if guard.code == "PROMPT_ATTACK":
            ticket = f" {route.output.get('escalation_id')}" if route and route.output else ""
            return (
                "That request carries prompt-attack signals, so it was stopped at the guardrail "
                f"and logged{ticket}. I don't have, and can't be given, the ability to change "
                "recall scope or release product through conversation. If you believe a hold is "
                "wrong, the path is a co-signed release request in the human console."
            )
        if guard.code == "INPUT_TOO_LARGE":
            return (
                "That input is larger than the 6,000 character limit. Send the relevant excerpt "
                "instead — I read documents as evidence, not as instructions."
            )
        return (
            "That request was stopped by the input guardrail and recorded. Nothing changed in "
            "the incident. Ask me for status, tracing, containment, or notifications."
        )


# ---------------------------------------------------------------------------
# Live Bedrock path
# ---------------------------------------------------------------------------


class BedrockConverseAgent:
    """Real Bedrock Converse tool-use loop, used when AWS credentials exist.

    Kept in the same package as the offline engine so the tool schema, the guard
    and the kernel are literally the same objects in both modes. This is the
    only place boto3 is imported, and it is imported lazily so the demo runs
    without it.
    """

    def __init__(
        self,
        *,
        model_id: str,
        region: str,
        guardrail_id: str | None = None,
        guardrail_version: str | None = None,
        system_prompt: str = "You are HOLD, a food-safety containment agent.",
    ) -> None:
        self.model_id = model_id
        self.region = region
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version
        self.system_prompt = system_prompt

    def tool_config(self) -> dict[str, Any]:
        from . import registry

        return {
            "tools": [
                {
                    "toolSpec": {
                        "name": t.name,
                        "description": t.summary,
                        "inputSchema": {
                            "json": {
                                "type": "object",
                                "properties": {
                                    p.name: {
                                        "type": "array" if p.type == "array<string>" else (
                                            "object" if p.type == "object" else (
                                                "integer" if p.type == "integer" else "string"
                                            )
                                        ),
                                        "description": p.description,
                                        **({"items": {"type": "string"}} if p.type == "array<string>" else {}),
                                        **({"enum": list(p.enum)} if p.enum else {}),
                                    }
                                    for p in t.params
                                },
                                "required": [p.name for p in t.params if p.required],
                            }
                        },
                    }
                }
                for t in registry.AGENT_TOOLS
            ]
        }

    def converse(self, messages: list[dict[str, Any]]) -> dict[str, Any]:  # pragma: no cover
        import boto3  # type: ignore

        client = boto3.client("bedrock-runtime", region_name=self.region)
        kwargs: dict[str, Any] = {
            "modelId": self.model_id,
            "messages": messages,
            "system": [{"text": self.system_prompt}],
            "toolConfig": self.tool_config(),
            "inferenceConfig": {"maxTokens": 2000, "temperature": 0.2},
        }
        if self.guardrail_id:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": self.guardrail_id,
                "guardrailVersion": self.guardrail_version or "DRAFT",
                "trace": "enabled",
            }
        return client.converse(**kwargs)


__all__ = ["Session", "Turn", "BedrockConverseAgent"]
