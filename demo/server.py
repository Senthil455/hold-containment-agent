"""Local operator console for HOLD.

Zero third-party dependencies: a stdlib HTTP server, the same kernel the tests
use, and a static single-page UI. Run it with:

    python demo/server.py

The console has two honest labels in the header: OFFLINE REPLAY (the walkthrough
is an authored script executed for real by the kernel) and LIVE BEDROCK (only
shown when AWS credentials are configured). The enforcement path is identical in
both cases.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hold import registry  # noqa: E402
from hold.cosign import CosignAuthority, payload_digest  # noqa: E402
from hold.domain import (  # noqa: E402
    AGENT,
    QA_DIRECTOR,
    Actor,
    ActorKind,
    ContainmentState,
    Decision,
)
from hold.engine import Session  # noqa: E402
from hold.guardrail import InputGuard, guardrail_summary  # noqa: E402
from hold.kernel import AuthorityKernel  # noqa: E402
from hold.lattice import containment_score, delta, dominant, well_formed  # noqa: E402
from hold.ledger import Ledger  # noqa: E402
from hold.policy import LAYERS, RULES  # noqa: E402
from hold.scenario import STEPS, route  # noqa: E402
from hold.seed import (  # noqa: E402
    INCIDENT_BRIEF,
    OPEN_QUESTIONS,
    build_world,
    implicated_lots,
)
from hold.util import iso  # noqa: E402


STATIC = Path(__file__).resolve().parent / "static"
COSIGN_KEY = b"hold-local-demo-key-not-for-production"


def _short(h: str | None, n: int = 10) -> str:
    return (h or "")[:n]


class Demo:
    """One incident, one kernel, one ledger. Reset starts a new run."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.world = build_world()
        self.guard = InputGuard()
        self.cosign = CosignAuthority(COSIGN_KEY)
        self.ledger = Ledger()
        self.kernel = AuthorityKernel(self.world, self.ledger, self.cosign,
                                      notify_rate_per_minute=4)
        self.session = Session(self.world, self.kernel, self.guard, self.ledger, router=route)
        self.run_id = uuid.uuid4().hex[:8]
        self.cursor = 0
        self.turns: list[dict[str, Any]] = []
        self.stress: dict[str, Any] | None = None
        self.pending: dict[str, Any] = {}

    def reset(self) -> None:
        self.__init__()  # noqa: PLC2801 - deliberate full reset

    # -- derived views ----------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        st = self.kernel.state
        implicated = implicated_lots()
        shipped = sum(
            s.units for s in self.world.shipments if s.lot_id in st.recalled
        )
        return {
            "score": containment_score(st, self.world, implicated),
            "generation": st.generation,
            "held": len(st.held),
            "recalled": len(st.recalled),
            "notified": len(st.notified),
            "released": len(st.released),
            "held_units": sum(self.world.lots[l].units for l in st.held),
            "cases_in_market": shipped,
            "accounts_total": len(self.world.customers),
            "implicated_total": len(implicated),
            "monotone": dominant(st, ContainmentState()),
        }

    def lot_rows(self) -> list[dict[str, Any]]:
        st = self.kernel.state
        rows = []
        for lot in self.world.lots.values():
            ships = self.world.shipments_for(lot.lot_id)
            rows.append({
                "lot_id": lot.lot_id,
                "sku": lot.sku,
                "product": lot.product,
                "facility": lot.facility,
                "supplier_id": lot.supplier_id,
                "vat": lot.vat,
                "produced_on": lot.produced_on,
                "best_by": lot.best_by,
                "units": lot.units,
                "uom": lot.uom,
                "risk": lot.risk.value,
                "swab": lot.swab,
                "state": st.lot_state(lot.lot_id).value,
                "implicated": lot.lot_id in implicated_lots(),
                "shipped_units": sum(s.units for s in ships),
                "accounts": len(ships),
                "note": lot.note,
            })
        order = {"RECALLED": 0, "HELD": 1, "SHIPPABLE": 2, "RELEASED": 3}
        rows.sort(key=lambda r: (order.get(r["state"], 9), r["lot_id"]))
        return rows

    def bootstrap(self) -> dict[str, Any]:
        st = self.kernel.state
        chain = self.ledger.verify()
        return {
            "run_id": self.run_id,
            "mode": "OFFLINE_REPLAY",
            "incident": {
                "id": self.world.incident_id,
                "title": self.world.incident_title,
                "tenant": self.world.tenant_id,
                "opened_at": self.world.opened_at,
                "brief": INCIDENT_BRIEF,
                "open_questions": list(OPEN_QUESTIONS),
                "facilities": list(self.world.facilities),
            },
            "state": st.summary(),
            "metrics": self.metrics(),
            "lots": self.lot_rows(),
            "customers": [
                {"customer_id": c.customer_id, "name": c.name, "kind": c.kind,
                 "city": c.city, "region": c.region}
                for c in self.world.customers.values()
            ],
            "shipments": [
                {"shipment_id": s.shipment_id, "lot_id": s.lot_id,
                 "customer_id": s.customer_id, "units": s.units, "shipped_on": s.shipped_on}
                for s in self.world.shipments
            ],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.world.edges],
            "tools": registry.all_json(),
            "agent_tools": [t.name for t in registry.AGENT_TOOLS],
            "rules": [r.to_json() for r in RULES],
            "layers": list(LAYERS),
            "guardrail": guardrail_summary(),
            "scenario": [
                {"index": i, "key": s.key, "label": s.label, "user": s.user, "intent": s.intent}
                for i, s in enumerate(STEPS)
            ],
            "cursor": self.cursor,
            "turns": self.turns,
            "ledger": {
                "length": len(self.ledger),
                "head": self.ledger.root(),
                "ok": chain.ok,
            },
            "requests": self.kernel.pending_requests(),
            "stress": self.stress,
            "timestamp": iso(),
        }

    # -- actions ----------------------------------------------------------

    def step(self) -> dict[str, Any]:
        if self.cursor >= len(STEPS):
            return {"done": True, "turn": None, "cursor": self.cursor}
        step = STEPS[self.cursor]
        turn = self.session.turn(step.user, calls=step.calls, final=step.compose)
        payload = {
            "index": self.cursor,
            "key": step.key,
            "label": step.label,
            "intent": step.intent,
            "turn": turn.to_json(),
            "state": self.kernel.state.summary(),
            "metrics": self.metrics(),
            "ledger": {"length": len(self.ledger), "head": self.ledger.root()},
        }
        self.turns.append({**payload})
        self.cursor += 1
        return {"done": False, **payload, "cursor": self.cursor}

    def free_turn(self, text: str) -> dict[str, Any]:
        turn = self.session.turn(text, calls=None, final=None)
        if not turn.final:
            turn.final = self._fallback_text(turn)
        payload = {
            "index": None,
            "key": "free",
            "label": "Operator",
            "intent": "Free-text request routed by the offline intent router.",
            "turn": turn.to_json(),
            "state": self.kernel.state.summary(),
            "metrics": self.metrics(),
            "ledger": {"length": len(self.ledger), "head": self.ledger.root()},
        }
        self.turns.append(payload)
        return payload

    def _fallback_text(self, turn: Any) -> str:
        st = self.kernel.state
        lines = [
            f"Current scope: {len(st.recalled)} lot(s) recalled, {len(st.held)} held, "
            f"{len(st.notified)} account(s) notified, {len(st.released)} released.",
        ]
        for r in turn.results:
            if r.blocked:
                lines.append(f"`{r.tool}` was refused: {r.code} at the {r.layer} layer.")
            else:
                lines.append(f"`{r.tool}` completed ({r.decision.value.lower()}).")
        lines.append(
            "I can hold lots, widen the recall, notify affected accounts and escalate. "
            "Release, narrowing, deletion and export are outside my authority."
        )
        return "\n\n".join(lines)

    def lab(self, tool: str, args: dict[str, Any], actor_id: str) -> dict[str, Any]:
        actor: Actor = AGENT
        if actor_id == "qa_director":
            actor = QA_DIRECTOR
        result = self.kernel.invoke(actor, tool, args)
        return {
            "result": result.to_json(),
            "actor": actor.to_json(),
            "metrics": self.metrics(),
            "layers": self._layer_trace(result, actor),
        }

    def _layer_trace(self, result: Any, actor: Actor) -> list[dict[str, Any]]:
        """Show which layers were actually in the path, not a decorative chain.

        The boundary lab calls ``kernel.invoke`` directly, so the model-side
        guardrail and the AWS-side identity/gateway policy are *not* exercised.
        Marking them "passed" would be dishonest: the whole point of the lab is
        that the inner boundary holds even when the outer layers are absent.
        """
        order = ["GUARDRAIL", "IDENTITY", "POLICY", "CAPABILITY", "KERNEL", "HUMAN", "LEDGER"]
        hit = result.layer if result.layer in order else ("KERNEL" if not result.blocked else "CAPABILITY")
        idx = order.index(hit)
        upstream_external = {"GUARDRAIL", "IDENTITY", "POLICY"}
        out = []
        for i, layer in enumerate(order):
            if i < idx:
                if layer in upstream_external:
                    state = "not_in_path"
                elif layer == "HUMAN" and actor.kind.value != "human":
                    state = "not_in_path"
                else:
                    state = "passed"
            elif i == idx:
                state = "stopped" if result.blocked else "passed"
            elif layer == "LEDGER" and result.receipt:
                state = "passed"
            elif layer == "HUMAN" and actor.kind.value != "human":
                state = "not_in_path"
            else:
                state = "not_reached"
            out.append({"layer": layer, "state": state})
        return out

    def request_release(self, lots: list[str], justification: str) -> dict[str, Any]:
        r = self.kernel.invoke(AGENT, "request_release",
                               {"lots": lots, "justification": justification})
        if not r.blocked:
            req = self.kernel.pending_requests()[-1]
            self.pending[req["request_id"]] = req
        return {"result": r.to_json(), "requests": self.kernel.pending_requests(),
                "metrics": self.metrics()}

    def human_action(self, action: str, lots: list[str], justification: str,
                     approver: str = "human:vp-quality") -> dict[str, Any]:
        payload = {"lots": sorted(lots), "justification": justification}
        token = self.cosign.issue(
            action=action,
            requester=QA_DIRECTOR.id,
            approver=approver,
            payload=payload,
        )
        args = {**payload, "cosign": token}
        r = self.kernel.invoke(QA_DIRECTOR, action, args)
        if not r.blocked and action == "release_hold":
            self.kernel.resolve_requests(lots)
        return {
            "result": r.to_json(),
            "state": self.kernel.state.summary(),
            "metrics": self.metrics(),
            "requests": self.kernel.pending_requests(),
        }

    def ledger_view(self) -> dict[str, Any]:
        status = self.ledger.verify()
        entries = []
        for e in self.ledger.entries(newest_first=True, limit=250):
            b = e.body
            d = b.get("delta") or {}
            entries.append({
                "seq": e.seq,
                "at": e.at,
                "tool": b.get("tool"),
                "effect": b.get("effect"),
                "actor": b.get("actor"),
                "decision": b.get("decision"),
                "code": b.get("code"),
                "layer": b.get("layer"),
                "flags": b.get("flags", []),
                "provenance": b.get("provenance", []),
                "delta": d,
                "args": b.get("args"),
                "hash": e.hash,
                "prev_hash": e.prev_hash,
            })
        return {"status": status.to_json(), "entries": entries}


class Handler(BaseHTTPRequestHandler):
    demo: Demo
    server_version = "HOLD/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if os.environ.get("HOLD_QUIET") != "1":
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- plumbing ---------------------------------------------------------

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path in ("/", "/index.html"):
                self._serve_file(STATIC / "index.html")
                return
            if path.startswith("/static/"):
                self._serve_file(STATIC / path.removeprefix("/static/"))
                return
            if path == "/api/bootstrap":
                with self.demo.lock:
                    self._json(200, self.demo.bootstrap())
                return
            if path == "/api/ledger":
                with self.demo.lock:
                    self._json(200, self.demo.ledger_view())
                return
            if path == "/api/export":
                with self.demo.lock:
                    bundle = {
                        "generated_at": iso(),
                        "run_id": self.demo.run_id,
                        "bootstrap": self.demo.bootstrap(),
                        "ledger": self.demo.ledger_view(),
                        "stress": self.demo.stress,
                    }
                body = json.dumps(bundle, ensure_ascii=False, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition",
                                 'attachment; filename="hold-ir-2041-evidence.json"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(404, {"error": "not found", "path": path})
        except Exception:
            traceback.print_exc()
            self._json(500, {"error": "internal", "trace": traceback.format_exc(limit=3)})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        data = self._read_json()
        try:
            with self.demo.lock:
                if path == "/api/reset":
                    self.demo.reset()
                    self._json(200, self.demo.bootstrap())
                    return
                if path == "/api/step":
                    self._json(200, self.demo.step())
                    return
                if path == "/api/turn":
                    text = str(data.get("text", ""))[:8000]
                    if not text.strip():
                        self._json(400, {"error": "empty text"})
                        return
                    self._json(200, self.demo.free_turn(text))
                    return
                if path == "/api/lab":
                    tool = str(data.get("tool", ""))
                    args = data.get("args") or {}
                    actor = str(data.get("actor", "agent"))
                    if not isinstance(args, dict):
                        args = {}
                    self._json(200, self.demo.lab(tool, args, actor))
                    return
                if path == "/api/human/request":
                    lots = [str(x) for x in (data.get("lots") or [])]
                    just = str(data.get("justification", "Reviewed the evidence."))
                    self._json(200, self.demo.request_release(lots, just))
                    return
                if path == "/api/human/action":
                    action = str(data.get("action", ""))
                    if action not in {"release_hold", "narrow_recall"}:
                        self._json(400, {"error": "unsupported human action"})
                        return
                    lots = [str(x) for x in (data.get("lots") or [])]
                    just = str(data.get("justification", "Co-signed in the human console."))
                    self._json(200, self.demo.human_action(action, lots, just))
                    return
                if path == "/api/ledger/verify":
                    status = self.demo.ledger.verify()
                    drill = None
                    if data.get("tamper"):
                        drill = shadow_tamper_drill(self.demo.ledger)
                    self._json(200, {"status": status.to_json(), "drill": drill})
                    return
                if path == "/api/stress/run":
                    from evals.run_stress import run_suite

                    self.demo.stress = run_suite()
                    self._json(200, self.demo.stress)
                    return
                self._json(404, {"error": "not found", "path": path})
        except Exception:
            traceback.print_exc()
            self._json(500, {"error": "internal", "trace": traceback.format_exc(limit=3)})

    def _serve_file(self, path: Path) -> None:
        try:
            resolved = path.resolve()
            if STATIC.resolve() not in resolved.parents and resolved != STATIC.resolve():
                self._json(403, {"error": "forbidden"})
                return
            if not resolved.is_file():
                self._json(404, {"error": "not found"})
                return
            ctype = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in {"application/javascript", "application/json"}:
                ctype += "; charset=utf-8"
            self._send(200, resolved.read_bytes(), ctype)
        except Exception:
            traceback.print_exc()
            self._json(500, {"error": "static"})


def shadow_tamper_drill(source: Ledger) -> dict[str, Any]:
    """Prove the chain verifies by mutating a *copy*.

    The live chain is evidence and is never touched. This replays the same
    entries into a shadow ledger, flips one field, and shows the verifier
    failing at exactly that sequence number.
    """
    shadow = Ledger()
    for entry in source.entries():
        shadow.append({k: v for k, v in entry.body.items() if k not in {"seq", "at"}},
                      at=entry.at)
    before = shadow.verify().to_json()
    target = max(2, len(shadow) // 2)
    shadow._tamper_for_demo(target, {"tool": "purge_ledger"})
    after = shadow.verify()
    return {
        "note": "Shadow copy. The live ledger was not modified.",
        "intact": before["ok"],
        "tampered_seq": target,
        "detected": not after.ok,
        "broken_at": after.broken_at,
        "reason": after.reason,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HOLD operator console")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8787")))
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)

    demo = Demo()
    Handler.demo = demo
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True

    print(f"HOLD console  ->  http://{args.host}:{args.port}")
    print(f"incident {demo.world.incident_id} · run {demo.run_id} · "
          f"{len(demo.world.lots)} lots · {len(registry.TOOLS)} tools")
    print("Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
