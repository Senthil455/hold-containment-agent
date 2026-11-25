"""Verify that the built wheel contains the runtime and guardrail config."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {
    "config/__init__.py",
    "config/guardrail.json",
    "hold/__init__.py",
    "hold/guardrail.py",
    "hold/kernel.py",
    "agent/runtime.py",
    "agent/service.py",
}


def main() -> int:
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if not wheels:
        print("no wheel found in dist/; run `python -m build --wheel` first", file=sys.stderr)
        return 1
    wheel = wheels[-1]
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    missing = sorted(REQUIRED - names)
    if missing:
        print(f"{wheel.name}: missing {missing}", file=sys.stderr)
        return 1
    print(f"wheel OK: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
