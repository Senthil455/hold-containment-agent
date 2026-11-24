"""Domain model for a food-safety lot containment incident.

The model is intentionally split in two:

    World              immutable-ish master data (lots, shipments, documents)
    ContainmentState   the small, monotone part of the world that this system
                       is allowed to change

Keeping containment in its own frozen value object is what makes the safety
property checkable: every action is a proposed transition, and the kernel can
compare the proposed state with the current one *before* committing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable, Mapping

from .util import digest


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Effect(str, Enum):
    """The authority effect of a tool call.

    This is the only taxonomy the policy layer cares about. A tool's effect is
    declared in the registry, not inferred from its name and never supplied by
    the model.
    """

    READ = "READ"
    TIGHTEN = "TIGHTEN"
    RELEASE = "RELEASE"
    DESTRUCT = "DESTRUCT"
    EXFIL = "EXFIL"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"


class ActorKind(str, Enum):
    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


class Channel(str, Enum):
    INTERNAL_QMS = "INTERNAL_QMS"
    SUPPLIER_DOC = "SUPPLIER_DOC"
    CUSTOMER_EMAIL = "CUSTOMER_EMAIL"
    EXTERNAL_WEB = "EXTERNAL_WEB"
    OPERATOR = "OPERATOR"


class Trust(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class Risk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class LotState(str, Enum):
    SHIPPABLE = "SHIPPABLE"
    HELD = "HELD"
    RECALLED = "RECALLED"
    RELEASED = "RELEASED"
    DISPOSITIONED = "DISPOSITIONED"


# ---------------------------------------------------------------------------
# Actors
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Actor:
    id: str
    kind: ActorKind
    display: str
    roles: frozenset[str] = frozenset()

    @property
    def is_human(self) -> bool:
        return self.kind is ActorKind.HUMAN

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind.value, "display": self.display,
                "roles": sorted(self.roles)}


AGENT = Actor("agent:hold", ActorKind.AGENT, "HOLD agent", frozenset({"containment"}))
SYSTEM = Actor("system:kernel", ActorKind.SYSTEM, "Containment kernel", frozenset({"system"}))
QA_DIRECTOR = Actor("human:qa-director", ActorKind.HUMAN, "QA Director (demo key)",
                    frozenset({"qa_director", "release_authority"}))
OPERATOR = Actor("human:operator", ActorKind.HUMAN, "Line operator", frozenset({"operator"}))


# ---------------------------------------------------------------------------
# Master data
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Lot:
    lot_id: str
    sku: str
    product: str
    facility: str
    supplier_id: str
    vat: str
    produced_on: str
    best_by: str
    units: int
    uom: str
    risk: Risk
    swab: str  # e.g. "PRESUMPTIVE_POSITIVE", "NEGATIVE", "PENDING"
    note: str = ""


@dataclass(frozen=True, slots=True)
class Customer:
    """A ship-to account.

    Note what is absent: there is no email field, no phone field and no
    free-text address here. The agent operates on customer *identifiers*.
    Contact data lives in the notification service, which composes from a fixed
    template and resolves recipients itself. That is a structural answer to
    "exfiltrate the customer list", not a filter bolted on afterwards.
    """

    customer_id: str
    name: str
    kind: str  # RETAIL | DISTRIBUTION | FRANCHISE
    city: str
    region: str


@dataclass(frozen=True, slots=True)
class Shipment:
    shipment_id: str
    lot_id: str
    customer_id: str
    units: int
    shipped_on: str


@dataclass(frozen=True, slots=True)
class SupplierDoc:
    doc_id: str
    supplier_id: str
    title: str
    kind: str
    received_at: str
    body: str


@dataclass(frozen=True, slots=True)
class TraceEdge:
    src: str
    dst: str
    kind: str  # INGREDIENT_OF | SPLIT_FROM | PACKED_AS


@dataclass(frozen=True, slots=True)
class World:
    tenant_id: str
    incident_id: str
    incident_title: str
    opened_at: str
    lots: Mapping[str, Lot]
    customers: Mapping[str, Customer]
    shipments: tuple[Shipment, ...]
    docs: Mapping[str, SupplierDoc]
    edges: tuple[TraceEdge, ...]
    facilities: tuple[str, ...]

    # -- lookups ----------------------------------------------------------

    def lot(self, lot_id: str) -> Lot | None:
        return self.lots.get(lot_id)

    def customers_for(self, lot_ids: Iterable[str]) -> set[str]:
        wanted = set(lot_ids)
        return {s.customer_id for s in self.shipments if s.lot_id in wanted}

    def shipments_for(self, lot_id: str) -> tuple[Shipment, ...]:
        return tuple(s for s in self.shipments if s.lot_id == lot_id)

    def upstream(self, lot_id: str) -> list[str]:
        out, seen, stack = [], {lot_id}, [lot_id]
        while stack:
            cur = stack.pop()
            for e in self.edges:
                if e.dst == cur and e.src not in seen:
                    seen.add(e.src)
                    out.append(e.src)
                    stack.append(e.src)
        return out

    def downstream(self, lot_id: str) -> list[str]:
        out, seen, stack = [], {lot_id}, [lot_id]
        while stack:
            cur = stack.pop()
            for e in self.edges:
                if e.src == cur and e.dst not in seen:
                    seen.add(e.dst)
                    out.append(e.dst)
                    stack.append(e.dst)
        return out

    def trace_closure(self, lot_ids: Iterable[str]) -> set[str]:
        """Everything reachable in both directions from a seed set."""
        out: set[str] = set()
        for lid in lot_ids:
            out.add(lid)
            out.update(self.upstream(lid))
            out.update(self.downstream(lid))
        return out

    def implicated_units(self) -> int:
        return sum(l.units for l in self.lots.values())


# ---------------------------------------------------------------------------
# The monotone state
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContainmentState:
    """The only mutable slice of the world, as a frozen value.

    Lattice (``dominant(a, b)`` means "a is at least as contained as b"):

        a.held     >= b.held        holds may only be added
        a.recalled >= b.recalled    recall scope may only grow
        a.notified >= b.notified    notifications may only be added
        a.released <= b.released    release set may only shrink

    ``generation`` is a monotone counter bumped by every widening action, so a
    replayed or reordered tool call can never be mistaken for a new decision.
    """

    generation: int = 0
    held: frozenset[str] = frozenset()
    recalled: frozenset[str] = frozenset()
    notified: frozenset[str] = frozenset()
    released: frozenset[str] = frozenset()
    dispositioned: frozenset[str] = frozenset()
    closed: bool = False
    updated_at: str = ""

    # -- monotone constructors -------------------------------------------

    def with_hold(self, lot_ids: Iterable[str], *, at: str) -> "ContainmentState":
        new = self.held | frozenset(lot_ids)
        if new == self.held:
            return self
        # New containment activity reopens a closed incident. Closure is not a
        # lock that can prevent a precautionary hold.
        return replace(
            self,
            held=new,
            closed=False,
            generation=self.generation + 1,
            updated_at=at,
        )

    def with_recall(self, lot_ids: Iterable[str], *, at: str) -> "ContainmentState":
        lots = frozenset(lot_ids)
        new_held = self.held | lots  # a recall always implies a hold
        new_recalled = self.recalled | lots
        if new_recalled == self.recalled and new_held == self.held:
            return self
        return replace(
            self,
            held=new_held,
            recalled=new_recalled,
            closed=False,
            generation=self.generation + 1,
            updated_at=at,
        )

    def with_notified(self, customer_ids: Iterable[str], *, at: str) -> "ContainmentState":
        new = self.notified | frozenset(customer_ids)
        if new == self.notified:
            return self
        return replace(self, notified=new, generation=self.generation + 1, updated_at=at)

    def with_release(self, lot_ids: Iterable[str], *, at: str) -> "ContainmentState":
        """Human-plane only. The agent's principal cannot reach this method
        through any tool, and the kernel refuses the whole effect class."""
        lots = frozenset(lot_ids)
        return replace(
            self,
            held=self.held - lots,
            released=self.released | lots,
            generation=self.generation + 1,
            updated_at=at,
        )

    def with_disposition(
        self, lot_ids: Iterable[str], *, disposition: str, at: str
    ) -> "ContainmentState":
        """Human-plane only. Resolve held inventory without pretending it is
        shippable: ``RELEASE`` records a release, every other disposition is
        recorded as a distinct terminal lot state."""
        lots = frozenset(lot_ids)
        if disposition == "RELEASE":
            return replace(
                self,
                held=self.held - lots,
                recalled=self.recalled - lots,
                released=self.released | lots,
                generation=self.generation + 1,
                updated_at=at,
            )
        return replace(
            self,
            held=self.held - lots,
            recalled=self.recalled - lots,
            dispositioned=self.dispositioned | lots,
            generation=self.generation + 1,
            updated_at=at,
        )

    # -- views ------------------------------------------------------------

    def lot_state(self, lot_id: str) -> LotState:
        if lot_id in self.recalled:
            return LotState.RECALLED
        if lot_id in self.held:
            return LotState.HELD
        if lot_id in self.dispositioned:
            return LotState.DISPOSITIONED
        if lot_id in self.released:
            return LotState.RELEASED
        return LotState.SHIPPABLE

    def digest(self) -> str:
        return digest(
            {
                "g": self.generation,
                "h": sorted(self.held),
                "r": sorted(self.recalled),
                "n": sorted(self.notified),
                "x": sorted(self.released),
                "d": sorted(self.dispositioned),
                "c": self.closed,
            }
        )

    def summary(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "held": sorted(self.held),
            "recalled": sorted(self.recalled),
            "notified": sorted(self.notified),
            "released": sorted(self.released),
            "dispositioned": sorted(self.dispositioned),
            "closed": self.closed,
            "updated_at": self.updated_at,
            "digest": self.digest(),
        }


# ---------------------------------------------------------------------------
# Requests / results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool: str
    args: Mapping[str, Any]
    # Provenance supplied by the *engine* (which document the turn read),
    # never by the model.
    provenance: tuple[str, ...] = ()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    COERCED = "COERCED"      # allowed, but the kernel reduced it to safe semantics
    DENY = "DENY"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"


@dataclass(frozen=True, slots=True)
class InvocationResult:
    decision: Decision
    code: str
    layer: str
    message: str
    tool: str
    effect: str
    args: Mapping[str, Any]
    output: Mapping[str, Any] = field(default_factory=dict)
    state: ContainmentState | None = None
    changed: bool = False
    receipt: str | None = None
    seq: int | None = None
    flags: tuple[str, ...] = ()
    attempted_loosening: bool = False

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.DENY

    def to_json(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "code": self.code,
            "layer": self.layer,
            "message": self.message,
            "tool": self.tool,
            "effect": self.effect,
            "args": dict(self.args),
            "output": dict(self.output),
            "state": self.state.summary() if self.state else None,
            "changed": self.changed,
            "receipt": self.receipt,
            "seq": self.seq,
            "flags": list(self.flags),
            "attempted_loosening": self.attempted_loosening,
        }
