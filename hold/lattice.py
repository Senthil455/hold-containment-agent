"""The containment lattice, and the checks that make it a real invariant.

Everything in this module is pure: state in, verdict out, no I/O. That means
the safety property can be tested exhaustively over random action sequences
without touching a database or a model (see ``tests/test_property_monotone.py``).

Definitions
-----------
``dominant(a, b)`` is true when state ``a`` is at least as contained as ``b``.

    a.held     superset of  b.held
    a.recalled superset of  b.recalled
    a.notified superset of  b.notified
    a.released subset of    b.released

``well_formed(s)`` is the set of structural invariants that must hold in *any*
reachable state, independent of monotonicity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .domain import ContainmentState, LotState, World


@dataclass(frozen=True, slots=True)
class Delta:
    """A human-readable description of a state transition."""

    held_added: tuple[str, ...]
    held_removed: tuple[str, ...]
    recalled_added: tuple[str, ...]
    recalled_removed: tuple[str, ...]
    notified_added: tuple[str, ...]
    notified_removed: tuple[str, ...]
    released_added: tuple[str, ...]
    released_removed: tuple[str, ...]
    generation_delta: int

    @property
    def loosens(self) -> bool:
        return bool(
            self.held_removed
            or self.recalled_removed
            or self.notified_removed
            or self.released_added
        )

    @property
    def tightens(self) -> bool:
        return bool(
            self.held_added or self.recalled_added or self.notified_added or self.released_removed
        )

    def to_json(self) -> dict[str, object]:
        return {
            "held_added": list(self.held_added),
            "held_removed": list(self.held_removed),
            "recalled_added": list(self.recalled_added),
            "recalled_removed": list(self.recalled_removed),
            "notified_added": list(self.notified_added),
            "notified_removed": list(self.notified_removed),
            "released_added": list(self.released_added),
            "released_removed": list(self.released_removed),
            "generation_delta": self.generation_delta,
            "loosens": self.loosens,
            "tightens": self.tightens,
        }


def delta(before: ContainmentState, after: ContainmentState) -> Delta:
    return Delta(
        held_added=tuple(sorted(after.held - before.held)),
        held_removed=tuple(sorted(before.held - after.held)),
        recalled_added=tuple(sorted(after.recalled - before.recalled)),
        recalled_removed=tuple(sorted(before.recalled - after.recalled)),
        notified_added=tuple(sorted(after.notified - before.notified)),
        notified_removed=tuple(sorted(before.notified - after.notified)),
        released_added=tuple(sorted(after.released - before.released)),
        released_removed=tuple(sorted(before.released - after.released)),
        generation_delta=after.generation - before.generation,
    )


def dominant(after: ContainmentState, before: ContainmentState) -> bool:
    """True when ``after`` is at least as contained as ``before``.

    This is the single function the ratchet is built on. It is small on
    purpose: a safety-critical predicate should be boring enough to read in one
    sitting and cheap enough to run on every single tool call.
    """
    return (
        after.held >= before.held
        and after.recalled >= before.recalled
        and after.notified >= before.notified
        and after.released <= before.released
        and after.generation >= before.generation
    )


def well_formed(state: ContainmentState, world: World) -> tuple[str, ...]:
    """Structural invariants that must hold in every reachable state.

    Returns a tuple of violations; empty means healthy.
    """
    problems: list[str] = []

    unknown = (state.held | state.recalled | state.released) - set(world.lots)
    if unknown:
        problems.append(f"unknown lot identifiers in state: {sorted(unknown)}")

    unknown_customers = state.notified - set(world.customers)
    if unknown_customers:
        problems.append(f"unknown customers in notified set: {sorted(unknown_customers)}")

    if state.held & state.released:
        problems.append(f"lots both held and released: {sorted(state.held & state.released)}")

    if not state.recalled <= state.held:
        problems.append(f"recalled but not held: {sorted(state.recalled - state.held)}")

    if state.generation < 0:
        problems.append("negative generation")

    # Every notified account must have received a lot that entered containment.
    # Once a lot is released or dispositioned it still counts, so a legitimate
    # narrow-then-release workflow does not trip this.
    contained = state.held | state.recalled | state.released | state.dispositioned
    reachable = world.customers_for(contained)
    if not state.notified <= reachable:
        problems.append(
            f"notified customers never received contained product: "
            f"{sorted(state.notified - reachable)}"
        )

    return tuple(problems)


def containment_score(
    state: ContainmentState,
    world: World,
    implicated: Iterable[str] | None = None,
) -> float:
    """0..100 progress meter for the operator console.

    Purely presentational. No decision anywhere depends on it, which is
    deliberate: a metric that gates a safety check invites gaming the metric.
    """
    total_lots = max(1, len(set(implicated) if implicated is not None else world.lots))
    total_customers = max(1, len(world.customers))
    in_scope = set(implicated) if implicated is not None else set(world.lots)
    lot_score = (
        len(state.held & in_scope) + 2 * len(state.recalled & in_scope)
    ) / (3 * total_lots)
    notice_score = len(state.notified) / total_customers
    return round(min(100.0, 100.0 * (0.72 * lot_score + 0.28 * notice_score)), 1)


def lot_states(state: ContainmentState, world: World) -> dict[str, str]:
    return {lot_id: state.lot_state(lot_id).value for lot_id in world.lots}


__all__ = [
    "Delta",
    "delta",
    "dominant",
    "well_formed",
    "containment_score",
    "lot_states",
    "LotState",
]
