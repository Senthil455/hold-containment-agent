"""Smoke test for the core: run the authored walkthrough end to end."""

from __future__ import annotations

import sys
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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
    score = containment_score(st, world, implicated_lots())
    chain = ledger.verify()
    print("=" * 78)
    print("FINAL STATE", st.summary())
    print("score", score)
    print("ledger", len(ledger), chain.to_json())
    print("pending", kernel.pending_requests())

    failures: list[str] = []

    def expect(name: str, condition: bool, detail: object = "") -> None:
        if not condition:
            failures.append(f"{name}: {detail}")

    expect("held lots", st.held == frozenset({"LOT-2288", "LOT-2291", "LOT-2292"}), st.held)
    expect("recall scope", st.recalled == frozenset({"LOT-2291", "LOT-2292"}), st.recalled)
    expect(
        "notified accounts",
        st.notified == frozenset({"CUS-441", "CUS-512", "CUS-608",
                                  "CUS-720", "CUS-803", "CUS-914"}),
        st.notified,
    )
    expect("nothing released", st.released == frozenset(), st.released)
    expect("nothing dispositioned", st.dispositioned == frozenset(), st.dispositioned)
    expect("incident stays open", st.closed is False, st.closed)
    expect("generation advanced", st.generation >= 3, st.generation)
    expect("ledger chain verifies", chain.ok, chain.to_json())
    expect("ledger entry count", len(ledger) == 19, len(ledger))
    expect("no pending release requests", kernel.pending_requests() == [],
           kernel.pending_requests())
    expect("containment score is positive", score > 0.0, score)

    if failures:
        print()
        print("SMOKE FAILED")
        for failure in failures:
            print(f"  - {failure}")
        raise SystemExit(1)

    print()
    print("SMOKE OK")


if __name__ == "__main__":
    main()
