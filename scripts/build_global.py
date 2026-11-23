#!/usr/bin/env python3
"""Build the public Global Threat Intelligence data from approved editorial records.

    python scripts/build_global.py           # validate + write global-intelligence/data/*.json
    python scripts/build_global.py --check   # validate only (CI)

Any error blocks the build and leaves the previously published data untouched.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tw.global_intel import build  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate only; do not write")
    args = ap.parse_args()
    outputs, errs = build(ROOT, write=not args.check)
    if errs:
        print("GLOBAL INTELLIGENCE BUILD BLOCKED (published data unchanged):", file=sys.stderr)
        for e in errs:
            print("  -", e, file=sys.stderr)
        return 1
    s = outputs["executive-summary.json"]
    print(f"OK: {s['counts']['active']} active, {s['counts']['historical']} historical, "
          f"{s['counts']['signals']} signals; summary {s['word_count']} words"
          + (" [DEMONSTRATION DATA]" if outputs["last-updated.json"]["demo"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
