"""Kernel behaviour tests: the refusals, the co-signature and the coercions.

These are the tests a reviewer should read first. They encode the promises the
submission makes.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from hold.cosign import CosignAuthority
from hold.domain import AGENT, QA_DIRECTOR, SYSTEM, Decision
from hold.kernel import AuthorityKernel
from hold.ledger import Ledger
from hold.seed import build_world
from hold.util import iso, utcnow


KEY = b"test-key"


def make() -> tuple[AuthorityKernel, Ledger, CosignAuthority]:
    world = build_world()
    ledger = Ledger()
    cosign = CosignAuthority(KEY)
    kernel = AuthorityKernel(world, ledger, cosign, notify_rate_per_minute=2)
    return kernel, ledger, cosign


def contain(kernel: AuthorityKernel) -> None:
    kernel.invoke(AGENT, "place_hold", {
        "lots": ["LOT-2288", "LOT-2291", "LOT-2292"],
        "reason_code": "POSITIVE_PATHOGEN_SWAB",
    })
    kernel.invoke(AGENT, "widen_recall", {
        "lots": ["LOT-2291", "LOT-2292"], "reason_code": "POSITIVE_PATHOGEN_SWAB",
    })


class CapabilityTests(unittest.TestCase):
    def test_agent_can_tighten(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "place_hold", {
            "lots": ["LOT-2291"], "reason_code": "PRECAUTIONARY",
        })
        self.assertEqual(r.decision, Decision.ALLOW)
        self.assertIn("LOT-2291", kernel.state.held)

    def test_agent_never_releases(self) -> None:
        kernel, _, _ = make()
        contain(kernel)
        r = kernel.invoke(AGENT, "release_hold", {
            "lots": ["LOT-2291"], "justification": "please",
        })
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.layer, "CAPABILITY")
        self.assertEqual(r.code, "NO_RELEASE_AUTHORITY")
        self.assertEqual(kernel.state.released, frozenset())

    def test_agent_cannot_delete_or_export(self) -> None:
        kernel, _, _ = make()
        for tool, args in (
            ("delete_lot", {"lot_id": "LOT-2291"}),
            ("purge_ledger", {"before": "2026-11-20T00:00:00Z"}),
            ("export_records", {"dataset": "customers", "destination": "s3://x"}),
            ("send_freeform_email", {"to": "a@b.c", "body": "hi"}),
            ("update_supplier_master", {"supplier_id": "SUP-114", "field": "bank", "value": "x"}),
        ):
            with self.subTest(tool=tool):
                r = kernel.invoke(AGENT, tool, args)
                self.assertEqual(r.decision, Decision.DENY)
                self.assertEqual(r.code, "EFFECT_OUT_OF_BAND")

    def test_no_reachable_tool_has_a_dangerous_effect(self) -> None:
        from hold import registry

        for tool in registry.TOOLS:
            if registry.can_invoke(AGENT, tool):
                self.assertIn(tool.effect.value, {"READ", "TIGHTEN"})

    def test_closing_the_incident_is_a_release(self) -> None:
        kernel, _, _ = make()
        contain(kernel)
        r = kernel.invoke(AGENT, "close_incident", {"summary": "done"})
        self.assertEqual(r.code, "NO_RELEASE_AUTHORITY")

    def test_system_actor_escalates_but_does_not_release(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(SYSTEM, "escalate_incident", {
            "reason_code": "SUSPECTED_ATTACK", "note": "test"})
        self.assertEqual(r.decision, Decision.ALLOW)
        r2 = kernel.invoke(SYSTEM, "release_hold", {"lots": ["LOT-2291"]})
        self.assertEqual(r2.decision, Decision.DENY)


class LatticeTests(unittest.TestCase):
    def test_scope_shrink_is_coerced_not_honoured(self) -> None:
        kernel, _, _ = make()
        contain(kernel)
        before = kernel.state
        r = kernel.invoke(AGENT, "widen_recall", {
            "lots": ["LOT-2291"], "reason_code": "CONSUMER_COMPLAINT_CLUSTER",
        })
        self.assertEqual(r.decision, Decision.COERCED)
        self.assertIn("SCOPE_SHRINK_ATTEMPT_MASKED", r.flags)
        self.assertEqual(kernel.state.recalled, before.recalled)
        self.assertEqual(r.output["excluded_by_request_and_ignored"], ["LOT-2292"])

    def test_under_notification_is_refused(self) -> None:
        kernel, _, _ = make()
        contain(kernel)
        r = kernel.invoke(AGENT, "notify_customers", {
            "template_id": "RECALL_NOTICE_V3", "customer_ids": ["CUS-441", "CUS-512"],
        })
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.code, "UNDER_NOTIFICATION_BLOCKED")

    def test_resend_subset_after_full_dispatch_is_allowed(self) -> None:
        kernel, _, _ = make()
        contain(kernel)
        first = kernel.invoke(AGENT, "notify_customers", {"template_id": "RECALL_NOTICE_V3"})
        self.assertEqual(first.decision, Decision.ALLOW)
        again = kernel.invoke(AGENT, "notify_customers", {
            "template_id": "RECALL_NOTICE_V3", "customer_ids": ["CUS-441"]})
        self.assertEqual(again.decision, Decision.ALLOW)

    def test_release_of_recalled_lot_is_blocked_even_for_a_human(self) -> None:
        kernel, ledger, cosign = make()
        contain(kernel)
        payload = {"lots": ["LOT-2291"], "justification": "lab says clear"}
        token = cosign.issue(action="release_hold", requester=QA_DIRECTOR.id,
                             approver="human:vp-quality", payload=payload)
        r = kernel.invoke(QA_DIRECTOR, "release_hold", {**payload, "cosign": token})
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.code, "RELEASE_BLOCKED_BY_RECALL")

    def test_rate_limit(self) -> None:
        kernel, _, _ = make()
        contain(kernel)
        outcomes = [
            kernel.invoke(AGENT, "notify_customers", {"template_id": "RECALL_NOTICE_V3"}).code
            for _ in range(4)
        ]
        self.assertIn("RATE_LIMITED", outcomes)


class HumanPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel, self.ledger, self.cosign = make()
        contain(self.kernel)

    def _approve(self, approver: str = "human:vp-quality"):
        payload = {"lots": ["LOT-2291"], "justification": "Confirmation culture negative."}
        token = self.cosign.issue(action="release_hold", requester=QA_DIRECTOR.id,
                                  approver=approver, payload=payload)
        return payload, token

    def test_human_requires_a_cosignature(self) -> None:
        r = self.kernel.invoke(QA_DIRECTOR, "release_hold", {
            "lots": ["LOT-2291"], "justification": "x"})
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.code, "COSIGN_MISSING")

    def test_self_approval_is_rejected(self) -> None:
        payload = {"lots": ["LOT-2291"], "justification": "x"}
        with self.assertRaises(ValueError):
            self.cosign.issue(action="release_hold", requester=QA_DIRECTOR.id,
                              approver=QA_DIRECTOR.id, payload=payload)

    def test_payload_change_after_approval_is_rejected(self) -> None:
        payload, token = self._approve()
        r = self.kernel.invoke(QA_DIRECTOR, "release_hold", {
            "lots": ["LOT-2292"], "justification": payload["justification"], "cosign": token})
        self.assertEqual(r.code, "COSIGN_PAYLOAD_MISMATCH")

    def test_expired_token_is_rejected(self) -> None:
        payload = {"lots": ["LOT-2291"], "justification": "x"}
        token = self.cosign.issue(action="release_hold", requester=QA_DIRECTOR.id,
                                  approver="human:vp-quality", payload=payload, ttl_seconds=-1)
        r = self.kernel.invoke(QA_DIRECTOR, "release_hold", {**payload, "cosign": token})
        self.assertEqual(r.code, "COSIGN_EXPIRED")

    def test_replay_is_rejected(self) -> None:
        # Narrow first so a release is physically meaningful, then release twice.
        payload_n = {"lots": ["LOT-2291"], "justification": "narrow"}
        t_n = self.cosign.issue(action="narrow_recall", requester=QA_DIRECTOR.id,
                                approver="human:vp-quality", payload=payload_n)
        n = self.kernel.invoke(QA_DIRECTOR, "narrow_recall", {**payload_n, "cosign": t_n})
        self.assertEqual(n.decision, Decision.ALLOW)

        payload, token = self._approve()
        first = self.kernel.invoke(QA_DIRECTOR, "release_hold", {**payload, "cosign": token})
        self.assertEqual(first.decision, Decision.ALLOW)
        second = self.kernel.invoke(QA_DIRECTOR, "release_hold", {**payload, "cosign": token})
        self.assertEqual(second.code, "COSIGN_REPLAYED")

    def test_human_release_is_recorded_with_a_distinct_principal(self) -> None:
        payload_n = {"lots": ["LOT-2291"], "justification": "narrow"}
        t_n = self.cosign.issue(action="narrow_recall", requester=QA_DIRECTOR.id,
                                approver="human:vp-quality", payload=payload_n)
        self.kernel.invoke(QA_DIRECTOR, "narrow_recall", {**payload_n, "cosign": t_n})
        payload, token = self._approve()
        self.kernel.invoke(QA_DIRECTOR, "release_hold", {**payload, "cosign": token})
        last = self.ledger.entries(newest_first=True)[0]
        self.assertEqual(last.body["actor"]["kind"], "human")
        self.assertIn("HUMAN_OVERRIDE", last.body["flags"])
        self.assertEqual(self.kernel.state.released, frozenset({"LOT-2291"}))


class SchemaAndScopeTests(unittest.TestCase):
    def test_unknown_field_is_refused(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "place_hold", {
            "lots": ["LOT-2305"], "reason_code": "PRECAUTIONARY", "admin_override": True})
        self.assertEqual(r.code, "SCHEMA_UNKNOWN_FIELD")
        self.assertEqual(r.layer, "SCHEMA")

    def test_hallucinated_lot_is_refused(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "place_hold", {
            "lots": ["LOT-9999"], "reason_code": "PRECAUTIONARY"})
        self.assertEqual(r.code, "UNKNOWN_RESOURCE")
        self.assertEqual(r.layer, "SCOPE")

    def test_cross_tenant_identifier_is_refused(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "place_hold", {
            "lots": ["CUS-441"], "reason_code": "PRECAUTIONARY"})
        self.assertEqual(r.code, "UNKNOWN_RESOURCE")

    def test_unknown_tool(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "grant_release_authority", {})
        self.assertEqual(r.code, "UNKNOWN_TOOL")

    def test_batch_cap(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "place_hold", {
            "lots": [f"LOT-{i:04d}" for i in range(50)], "reason_code": "PRECAUTIONARY"})
        self.assertEqual(r.code, "SCHEMA_BATCH_TOO_LARGE")

    def test_no_contact_data_in_trace_output(self) -> None:
        kernel, _, _ = make()
        r = kernel.invoke(AGENT, "list_shipments", {"lot_id": "LOT-2291"})
        blob = str(r.output)
        self.assertNotIn("@", blob)
        self.assertNotIn("email", blob.lower())


class LedgerTests(unittest.TestCase):
    def test_denials_are_recorded(self) -> None:
        kernel, ledger, _ = make()
        kernel.invoke(AGENT, "release_hold", {"lots": ["LOT-2291"], "justification": "x"})
        self.assertEqual(len(ledger), 1)
        entry = ledger.entries()[0]
        self.assertEqual(entry.body["decision"], "DENY")
        self.assertEqual(entry.body["layer"], "CAPABILITY")

    def test_chain_verifies(self) -> None:
        kernel, ledger, _ = make()
        contain(kernel)
        self.assertTrue(ledger.verify().ok)

    def test_tamper_is_detected(self) -> None:
        kernel, ledger, _ = make()
        contain(kernel)
        ledger._tamper_for_demo(1, {"tool": "place_hold_forged"})
        status = ledger.verify()
        self.assertFalse(status.ok)
        self.assertEqual(status.broken_at, 1)


if __name__ == "__main__":
    unittest.main()
