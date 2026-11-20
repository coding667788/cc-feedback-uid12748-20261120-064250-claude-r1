"""Load a cases.json document and execute it against a (possibly persistent)
SQLite database, returning the JSON-able result document."""

from __future__ import annotations

from .service import Service
from .store import Store


def run_cases(cases: dict, db_path: str | None = None, crash_hook=None) -> dict:
    store = Store(db_path) if db_path else Store.memory()
    try:
        svc = Service(store, crash_hook=crash_hook)
        # A fresh database applies the setup section; an already-initialised
        # database (a restarted phase reusing the same file) skips it.
        if cases.get("setup") and not svc.is_initialized():
            svc.setup(cases["setup"])
        results = [svc.execute(op) for op in cases.get("operations", [])]
        return {"results": results, "summary": svc.summary()}
    finally:
        store.close()
