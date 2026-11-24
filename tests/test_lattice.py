"""Lattice unit tests."""

from __future__ import annotations

import unittest

from hold.domain import ContainmentState, LotState
from hold.lattice import containment_score, delta, dominant, well_formed
from hold.seed import build_world, implicated_lots


class DominanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = build_world()
        self.base = ContainmentState(updated_at="2026-11-20T00:00:00Z")

    def test_growth_is_dominant(self) -> None:
        after = self.base.with_hold(["LOT-2291"], at="t")
        self.assertTrue(dominant(after, self.base))

    def test_shrinking_a_hold_is_not_dominant(self) -> None:
        held = self.base.with_hold(["LOT-2291"], at="t")
        shrunk = ContainmentState(
            generation=held.generation + 1,
            held=frozenset(),
            recalled=held.recalled,
            notified=held.notified,
            released=held.released,
            updated_at="t",
        )
        self.assertFalse(dominant(shrunk, held))
        self.assertTrue(delta(held, shrunk).loosens)

    def test_adding_to_released_is_not_dominant(self) -> None:
        released = self.base.with_release(["LOT-2250"], at="t")
        self.assertFalse(dominant(released, self.base))

    def test_generation_must_not_go_backwards(self) -> None:
        older = ContainmentState(generation=1, updated_at="t")
        newer = ContainmentState(generation=5, updated_at="t")
        self.assertFalse(dominant(older, newer))
        self.assertTrue(dominant(newer, older))

    def test_delta_is_specific(self) -> None:
        after = self.base.with_hold(["LOT-2291", "LOT-2292"], at="t").with_recall(
            ["LOT-2291"], at="t"
        )
        d = delta(self.base, after)
        self.assertEqual(d.held_added, ("LOT-2291", "LOT-2292"))
        self.assertEqual(d.recalled_added, ("LOT-2291",))
        self.assertTrue(d.tightens)
        self.assertFalse(d.loosens)

    def test_disposition_is_visible_and_terminal(self) -> None:
        held = self.base.with_hold(["LOT-2291"], at="t")
        after = held.with_disposition(["LOT-2291"], disposition="DESTROY", at="t")
        self.assertEqual(after.lot_state("LOT-2291"), LotState.DISPOSITIONED)
        self.assertNotIn("LOT-2291", after.held)
        d = delta(held, after)
        self.assertEqual(d.dispositioned_added, ("LOT-2291",))
        self.assertEqual(well_formed(after, self.world), ())


class WellFormedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = build_world()

    def test_fresh_state_is_well_formed(self) -> None:
        self.assertEqual(well_formed(ContainmentState(), self.world), ())

    def test_recall_without_hold_is_a_violation(self) -> None:
        s = ContainmentState(recalled=frozenset({"LOT-2291"}))
        self.assertTrue(any("recalled but not held" in p for p in well_formed(s, self.world)))

    def test_held_and_released_overlap_is_a_violation(self) -> None:
        s = ContainmentState(
            held=frozenset({"LOT-2291"}), released=frozenset({"LOT-2291"})
        )
        self.assertTrue(any("both held and released" in p for p in well_formed(s, self.world)))

    def test_held_and_dispositioned_overlap_is_a_violation(self) -> None:
        s = ContainmentState(
            held=frozenset({"LOT-2291"}), dispositioned=frozenset({"LOT-2291"})
        )
        self.assertTrue(
            any("both held and dispositioned" in p for p in well_formed(s, self.world))
        )

    def test_closed_incident_cannot_keep_active_containment(self) -> None:
        s = ContainmentState(held=frozenset({"LOT-2291"}), closed=True)
        self.assertTrue(
            any("closed incident still has active containment" in p
                for p in well_formed(s, self.world))
        )

    def test_notified_account_must_have_received_contained_product(self) -> None:
        # CUS-927 received LOT-2305 and LOT-2250, never the implicated lots.
        s = ContainmentState(
            held=frozenset({"LOT-2291"}), notified=frozenset({"CUS-927"})
        )
        self.assertTrue(any("never received contained product" in p for p in well_formed(s, self.world)))

    def test_notification_survives_a_narrow(self) -> None:
        # 441 has LOT-2291 in scope; narrowing the recall keeps the lot held, so
        # the notification stays traceable. This is the legitimate workflow.
        s = ContainmentState(
            held=frozenset({"LOT-2291", "LOT-2292"}),
            recalled=frozenset({"LOT-2291", "LOT-2292"}),
            notified=frozenset({"CUS-441", "CUS-608"}),
        )
        narrowed = ContainmentState(
            held=s.held,
            recalled=frozenset({"LOT-2291"}),
            notified=s.notified,
            generation=1,
        )
        self.assertEqual(well_formed(narrowed, self.world), ())

    def test_score_is_bounded(self) -> None:
        s = (
            ContainmentState()
            .with_hold(implicated_lots(), at="t")
            .with_recall(["LOT-2291", "LOT-2292"], at="t")
        )
        score = containment_score(s, self.world, implicated_lots())
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)
        self.assertGreater(score, 50.0)


if __name__ == "__main__":
    unittest.main()
