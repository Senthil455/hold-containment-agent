"""Regression tests for the local operator console plumbing."""

from __future__ import annotations

import unittest

from demo.server import Demo, shadow_tamper_drill
from hold.ledger import Ledger


class DemoTests(unittest.TestCase):
    def test_reset_keeps_the_same_lock_object(self) -> None:
        demo = Demo()
        lock = demo.lock
        run_id = demo.run_id

        demo.reset()

        self.assertIs(demo.lock, lock)
        self.assertNotEqual(demo.run_id, run_id)

    def test_empty_ledger_tamper_drill_is_safe(self) -> None:
        result = shadow_tamper_drill(Ledger())

        self.assertTrue(result["intact"])
        self.assertIsNone(result["tampered_seq"])
        self.assertFalse(result["detected"])
        self.assertIsNone(result["broken_at"])

    def test_disposition_resolves_a_pending_release_request(self) -> None:
        demo = Demo()
        demo.step()  # triage
        demo.step()  # hold and recall

        requested = demo.request_release(["LOT-2288"], "QA review before release")
        self.assertEqual(requested["result"]["decision"], "ALLOW")
        self.assertEqual(
            [r["status"] for r in requested["requests"] if r["lots"] == ["LOT-2288"]],
            ["AWAITING_COSIGN"],
        )

        denied = demo.request_release(["LOT-2291"], "release a recalled lot")
        self.assertEqual(denied["result"]["decision"], "DENY")
        self.assertEqual(denied["result"]["code"], "RELEASE_BLOCKED_BY_RECALL")

        resolved = demo.human_action(
            "approve_disposition", ["LOT-2288"], "destroy", disposition="DESTROY"
        )
        self.assertEqual(resolved["result"]["decision"], "ALLOW")
        self.assertEqual(
            [r["status"] for r in resolved["requests"] if r["lots"] == ["LOT-2288"]],
            ["RESOLVED"],
        )


if __name__ == "__main__":
    unittest.main()
