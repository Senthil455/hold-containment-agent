"""Smoke test for the core: run the authored walkthrough end to end."""

from __future__ import annotations

import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from hold.cosign import CosignAuthority
from hold.engine import Session
from hold.guardrail import InputGuard
from hold.kernel import AuthorityKernel
from hold.ledger import Ledger
from hold.scenario import STEPS, route
from hold.seed import build_world
from hold.lattice import containment_score
from hold.seed import implicated_lots


def main() -> None:
    world = build_world()
    ledger = Ledger()
    kernel = AuthorityKernel(world, ledger, CosignAuthority(b"demo-key"))
    session = Session(world, kernel, InputGuard(), ledger, router=route)

    for step in STEPS:
        turn = session.turn(step.user, calls=step.calls, final=step.compose)
        print("=" * 78)
        print(f"[{step.label}] {step.user}")
        for r in turn.results:
            mark = "DENY" if r.blocked else r.decision.value
            print(f"   {mark:7} {r.tool:22} {r.effect:14} {r.layer:11} {r.code}")
        print("-" * 78)
        print(turn.final)
        print()

    st = kernel.state
    print("=" * 78)
    print("FINAL STATE", st.summary())
    print("score", containment_score(st, world, implicated_lots()))
    print("ledger", len(ledger), ledger.verify().to_json())
    print("pending", kernel.pending_requests())


if __name__ == "__main__":
    main()
