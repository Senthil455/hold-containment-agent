"""The written rule set, as data.

Every rule is stated in plain language, mapped to the layer that enforces it,
and linked to the stress cases that exercise it. The console renders this
directly, so the published rule set and the running system cannot diverge: this
module is the single source of truth for both.

Enforcement layers, outermost first:

    GUARDRAIL   Bedrock Guardrails on input and output
    IDENTITY    AgentCore Identity + scoped IAM roles (agent has no data access)
    POLICY      Cedar at the AgentCore Gateway (effect-class allowlist)
    CAPABILITY  actor -> effect map, evaluated in-process before any handler
    KERNEL      this repo's lattice check on the proposed state transition
    HUMAN       two-person co-signature for the release plane
    LEDGER      hash-chained, append-only record of allows and denials
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    plain: str
    layers: tuple[str, ...]
    mechanism: str
    tests: tuple[str, ...] = ()
    plane: str = "agent"  # agent | human | both

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "plain": self.plain,
            "layers": list(self.layers),
            "mechanism": self.mechanism,
            "tests": list(self.tests),
            "plane": self.plane,
        }


LAYERS: tuple[dict[str, str], ...] = (
    {
        "id": "GUARDRAIL",
        "name": "Bedrock Guardrails",
        "blurb": "Denied topics on input and output, prompt-attack detection, PII masking, grounding.",
        "where": "Bedrock Runtime, in front of the model",
    },
    {
        "id": "IDENTITY",
        "name": "Identity & IAM",
        "blurb": "The runtime role can invoke Bedrock and the guardrail. It has no S3 or DynamoDB permissions at all.",
        "where": "AgentCore Runtime execution role",
    },
    {
        "id": "POLICY",
        "name": "Gateway policy",
        "blurb": "Cedar allowlist on the effect class carried by each tool. Default deny.",
        "where": "AgentCore Gateway",
    },
    {
        "id": "CAPABILITY",
        "name": "Capability map",
        "blurb": "Principal -> effect set, checked in-process before a handler is selected.",
        "where": "Containment kernel",
    },
    {
        "id": "KERNEL",
        "name": "Containment lattice",
        "blurb": "The proposed state must be at least as contained as the current one, or the call is refused.",
        "where": "Containment kernel",
    },
    {
        "id": "HUMAN",
        "name": "Two-person release",
        "blurb": "Release, narrowing and closure require a human principal plus a payload-bound co-signature.",
        "where": "Human console + payload-bound co-signature",
    },
    {
        "id": "LEDGER",
        "name": "Sealed ledger",
        "blurb": "Hash-chained record of every attempt, allow and denial. WORM storage; no delete path exists.",
        "where": "DynamoDB + S3 Object Lock",
    },
)


RULES: tuple[Rule, ...] = (
    Rule(
        id="R1",
        title="One direction only",
        plain=(
            "The agent may place holds, widen a recall, notify affected accounts, and "
            "escalate. It may never release a hold, narrow a recall, close an incident, "
            "delete a record, or bulk-export data. Those are not permissions it has, so "
            "no amount of asking changes the answer."
        ),
        layers=("CAPABILITY", "POLICY", "IDENTITY"),
        mechanism=(
            "Tool effects are declared in the registry and cannot be supplied by the model. "
            "The agent principal holds only READ and TIGHTEN. The Cedar policies in "
            "infra/policy repeat the same allowlist for deployments that put the tool plane "
            "behind AgentCore Gateway."
        ),
        tests=("S01", "S02", "S04", "S06", "S07"),
    ),
    Rule(
        id="R2",
        title="Scope comes from the trace, not from the sentence",
        plain=(
            "The agent cannot invent lot numbers or account numbers. Every identifier it "
            "names must exist in this tenant's trace data, and recall scope is computed by "
            "the kernel, never copied from the request."
        ),
        layers=("KERNEL", "POLICY"),
        mechanism=(
            "Identifier allowlist derived from the incident trace, plus tenant scoping on "
            "every read. Unknown identifiers are refused with UNKNOWN_RESOURCE."
        ),
        tests=("S13", "S15"),
    ),
    Rule(
        id="R3",
        title="The ratchet",
        plain=(
            "Every change must leave the recall at least as contained as it was. Holds and "
            "recall scope may grow, notifications may be added, the release set may only "
            "shrink. If a request would loosen containment, it is refused or reduced to "
            "its safe part, and the attempt is recorded."
        ),
        layers=("KERNEL",),
        mechanism=(
            "A containment lattice over four sets plus a monotone generation counter. "
            "dominant(after, before) is evaluated on the committed state, not on the "
            "model's description of it."
        ),
        tests=("S05", "S12", "S14"),
    ),
    Rule(
        id="R4",
        title="No self-approval",
        plain=(
            "Releasing product needs a named human, a second person's signature, and a "
            "signature that covers the exact lots and the exact justification. Approvals "
            "expire in fifteen minutes and work once."
        ),
        layers=("HUMAN", "CAPABILITY", "LEDGER"),
        mechanism=(
            "HMAC-SHA256 over {action, requester, payload digest, approver, nonce, expiry}. "
            "Single use, TTL-bound, approver != requester, and bound to the requesting "
            "principal so a stolen token cannot be replayed by the agent."
        ),
        tests=("S11",),
        plane="human",
    ),
    Rule(
        id="R5",
        title="Documents are data, not orders",
        plain=(
            "Supplier certificates, customer emails, and web content are untrusted. They "
            "may raise an alarm and cause tighter containment. They can never justify "
            "loosening anything, and instructions inside them are never followed."
        ),
        layers=("KERNEL", "GUARDRAIL"),
        mechanism=(
            "Canary-delimited quarantine blocks with provenance, plus an injection scanner. "
            "Crucially, the lattice already makes untrusted input harmless as an escalation "
            "vector: the worst it can cause is an unnecessary hold."
        ),
        tests=("S03", "S08", "S16"),
    ),
    Rule(
        id="R6",
        title="Least data",
        plain=(
            "The agent works with account identifiers, not people. It never sees an email "
            "address or a phone number, and it cannot compose a free-form message. Notices "
            "come from approved templates and are sent by the notification service."
        ),
        layers=("IDENTITY", "KERNEL", "GUARDRAIL"),
        mechanism=(
            "Contact data is not in the agent's data model at all. The notify tool accepts "
            "a template id and optional account ids; the service resolves recipients and "
            "refuses any account that did not receive recalled product."
        ),
        tests=("S06", "S10"),
    ),
    Rule(
        id="R7",
        title="No destructive path",
        plain=(
            "Nothing in this system can delete a lot, a shipment, or an audit entry. The "
            "ledger is append-only; the deployment bucket uses Object Lock compliance mode."
        ),
        layers=("CAPABILITY", "IDENTITY", "LEDGER"),
        mechanism=(
            "No delete tool is reachable from the containment plane; the admin-plane "
            "catalogue entries exist only so the boundary can be tested. The runtime role "
            "has an explicit IAM Deny on delete actions, and the ledger bucket uses Object "
            "Lock in compliance mode."
        ),
        tests=("S07",),
    ),
    Rule(
        id="R8",
        title="Stay in your lane",
        plain=(
            "The agent does not give legal or medical advice, does not declare food safe, "
            "and does not discuss liability, compensation, or press. It routes those "
            "questions to a qualified human."
        ),
        layers=("GUARDRAIL",),
        mechanism=(
            "Denied topics in Bedrock Guardrails on both input and output, mirrored "
            "deterministically offline so the tests are reproducible."
        ),
        tests=("S09", "S10"),
    ),
    Rule(
        id="R9",
        title="Every attempt is on the record",
        plain=(
            "Every tool attempt and every blocked prompt is written down, including the "
            "ones that were refused. The "
            "record is hash-chained so any edit is detectable, and it carries which layer "
            "made the decision."
        ),
        layers=("LEDGER",),
        mechanism=(
            "SHA-256 chain over canonical JSON, one entry per invocation, including denials. "
            "The demo keeps the chain in memory; the CDK stack provisions the Object Lock "
            "bucket and the tool plane is expected to seal the daily root there. "
            "Verification is a first-class API."
        ),
        tests=("S17",),
        plane="both",
    ),
    Rule(
        id="R10",
        title="Fail closed, then escalate",
        plain=(
            "When the agent is uncertain, it holds more product and asks a human. It never "
            "releases and asks afterwards. Ambiguity is a reason to contain, not a reason "
            "to wait."
        ),
        layers=("KERNEL", "HUMAN"),
        mechanism=(
            "Read failures and validation errors do not produce an empty scope that could be "
            "mistaken for 'nothing affected'; they produce an escalation and an explicit "
            "INCOMPLETE evidence flag."
        ),
        tests=("S14", "S18"),
    ),
    Rule(
        id="R11",
        title="Bounded blast radius",
        plain=(
            "Batch sizes, notification rates, turn budgets and note lengths are capped. A "
            "looping or panicking agent cannot spam every customer in the database."
        ),
        layers=("KERNEL",),
        mechanism=(
            "Per-tool batch caps, a token bucket on outbound notifications, and a step budget "
            "per conversation turn."
        ),
        tests=("S12",),
    ),
    Rule(
        id="R12",
        title="Human override is recorded, not hidden",
        plain=(
            "A human can overrule the agent. When they do, the system records who, when, on "
            "what evidence, and what the agent had concluded. The ratchet binds the machine, "
            "not the accountable person."
        ),
        layers=("HUMAN", "LEDGER"),
        mechanism=(
            "Human-plane actions are written to the same chain with a distinct principal, "
            "the co-signature reference, and the agent's dissent attached."
        ),
        tests=("S11",),
        plane="human",
    ),
)


def by_id(rule_id: str) -> Rule | None:
    return next((r for r in RULES if r.id == rule_id), None)


def as_json() -> list[dict[str, Any]]:
    return [r.to_json() for r in RULES]


__all__ = ["Rule", "RULES", "LAYERS", "by_id", "as_json"]
