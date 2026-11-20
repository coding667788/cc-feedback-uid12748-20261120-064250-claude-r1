"""Command line entry point:

    python -m solution --input cases.json --output result.json [--db STATE.db]

Without --db the run is self-contained in memory.  With --db the state
persists across processes, which is how the restart / multi-process
interleaving scenarios are driven.
"""

from __future__ import annotations

import argparse
import json
import sys

from .runner import run_cases


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="solution")
    parser.add_argument("--input", required=True, help="cases.json path")
    parser.add_argument("--output", required=True, help="result.json path")
    parser.add_argument("--db", default=None, help="SQLite state file (optional)")
    args = parser.parse_args(argv)

    with open(args.input, encoding="utf-8") as f:
        cases = json.load(f)

    out = run_cases(cases, db_path=args.db)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    results = out["results"]
    ok = sum(1 for r in results if r["status"] == "ok")
    err = len(results) - ok
    print(
        f"processed {len(results)} operations: {ok} ok, {err} error; "
        f"sessions_total={out['summary']['sessions_total']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
