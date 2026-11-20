"""Subprocess worker used by the concurrency / crash-recovery tests.

Usage:
    python -m solution.worker --db DB --ops OPS.json --out OUT.json

Environment knobs (all optional):
    SIM_WAIT_BARRIER    path; the worker blocks until this file exists
    SIM_SIGNAL_BARRIER  path; touched after all operations finished
    SIM_CRASH_AFTER     "session_insert" | "commit" -- os._exit(3) at that
                        point inside redeem, simulating an abrupt kill of the
                        writing process
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .service import Service
from .store import Store


def _wait_barrier(path: str, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="solution.worker")
    parser.add_argument("--db", required=True)
    parser.add_argument("--ops", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    wait = os.environ.get("SIM_WAIT_BARRIER")
    if wait and not _wait_barrier(wait):
        print("barrier timeout", file=sys.stderr)
        return 2

    crash_after = os.environ.get("SIM_CRASH_AFTER")

    def crash_hook(point):
        if point == crash_after:
            # abrupt kill: no cleanup, no output, uncommitted work is lost
            os._exit(3)

    with open(args.ops, encoding="utf-8") as f:
        ops = json.load(f)["operations"]

    store = Store(args.db)
    svc = Service(store, crash_hook=crash_hook)
    results = [svc.execute(op) for op in ops]
    store.close()

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, indent=2, sort_keys=True)

    signal = os.environ.get("SIM_SIGNAL_BARRIER")
    if signal:
        open(signal, "w").close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
