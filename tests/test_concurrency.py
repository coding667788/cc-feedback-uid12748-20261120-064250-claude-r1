"""Multi-process interleaving and crash-recovery tests.

Each scenario is driven by independent OS processes (``python -m
solution.worker``) sharing one SQLite database file, coordinated through
barrier files so the interleaving is fixed and reproducible:

1. duplicate-callback contention   -- two processes race the same claim id
2. scope shrink before redeem      -- shrink commits before redeem starts
3. old-device callback arrives late-- reset commits before callback runs
4. kill after session insert       -- uncommitted work must vanish
5. kill after commit               -- receipt survives; replay is idempotent
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from solution.runner import run_cases  # noqa: E402
from solution.store import Store  # noqa: E402

SETUP = {
    "tenants": [{"tenant_id": "t1"}],
    "providers": [{"provider_id": "p1", "tenant_id": "t1",
                   "issuer": "https://idp.example"}],
    "clients": [{"client_id": "c1", "tenant_id": "t1",
                 "callbacks": ["https://app.example/cb"],
                 "scopes": ["read", "write"]}],
    "devices": [{"device_id": "d1", "tenant_id": "t1", "generation": 1}],
}

CHALLENGE = {"request_id": "w-ch", "op": "challenge", "now": 100,
             "tenant_id": "t1", "provider_id": "p1", "client_id": "c1",
             "device_id": "d1", "callback": "https://app.example/cb",
             "scopes": ["read", "write"], "verifier": "v", "nonce": "N1",
             "expires_at": 9000}

CLAIM = {"claim_id": "CL-W", "challenge_id": "CH-w-ch",
         "iss": "https://idp.example", "aud": "c1", "sub": "alice",
         "iat": 150, "exp": 8000}

CALLBACK = {"request_id": "w-cb", "op": "callback", "now": 200,
            "challenge_id": "CH-w-ch", "claim": CLAIM}

REDEEM = {"request_id": "w-rd", "op": "redeem", "now": 300,
          "credential_id": "CR-w-cb", "callback": "https://app.example/cb",
          "client_id": "c1", "verifier": "v", "scopes": ["read", "write"]}


def build_db(db_path, operations):
    run_cases({"setup": SETUP, "operations": operations}, db_path=str(db_path))


def summary_of(db_path):
    return run_cases({"operations": []}, db_path=str(db_path))["summary"]


def run_worker(db_path, ops, out_path, env_extra=None):
    ops_path = out_path.with_suffix(".ops.json")
    ops_path.write_text(json.dumps({"operations": ops}), encoding="utf-8")
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "solution.worker",
         "--db", str(db_path), "--ops", str(ops_path), "--out", str(out_path)],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )


def read_out(out_path):
    return json.loads(out_path.read_text(encoding="utf-8"))["results"]


class TestInterleavings(unittest.TestCase):
    def test_duplicate_callback_contention(self):
        # Two processes submit the SAME claim id concurrently for the same
        # challenge: exactly one may consume it.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "state.db"
            build_db(db, [CHALLENGE])
            barrier = tmp / "go.barrier"
            env = {"SIM_WAIT_BARRIER": str(barrier)}
            cb1 = dict(CALLBACK, request_id="w-cb-1")
            cb2 = dict(CALLBACK, request_id="w-cb-2")
            out1, out2 = tmp / "o1.json", tmp / "o2.json"
            import threading
            procs = {}

            def go(ops, out, tag):
                procs[tag] = run_worker(db, [ops], out, env)

            t1 = threading.Thread(target=go, args=(cb1, out1, "a"))
            t2 = threading.Thread(target=go, args=(cb2, out2, "b"))
            t1.start(); t2.start()
            import time
            time.sleep(2.0)          # both workers are parked on the barrier
            barrier.touch()          # release both at the same instant
            t1.join(); t2.join()

            self.assertEqual(procs["a"].returncode, 0, procs["a"].stderr)
            self.assertEqual(procs["b"].returncode, 0, procs["b"].stderr)
            r1, r2 = read_out(out1)[0], read_out(out2)[0]
            outcomes = sorted([
                ("ok" if r["status"] == "ok" else r["error"]) for r in (r1, r2)
            ])
            self.assertEqual(outcomes, ["E_CLAIM_REPLAYED", "ok"])
            summary = summary_of(db)
            self.assertEqual(summary["claims_consumed"], 1)
            self.assertEqual(summary["credentials"],
                             {"issued": 1, "consumed": 0, "invalidated": 0})

    def test_scope_shrink_before_redeem(self):
        # The shrink commits before the redeem transaction begins: the
        # credential must already be invalidated.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "state.db"
            build_db(db, [CHALLENGE, CALLBACK])
            barrier = tmp / "shrunk.barrier"
            shrink = {"request_id": "w-shrink", "op": "shrink_client_scopes",
                      "now": 250, "client_id": "c1", "scopes": ["read"]}
            out_redeem, out_shrink = tmp / "redeem.json", tmp / "shrink.json"
            import threading
            procs = {}

            def do_redeem():
                procs["redeem"] = run_worker(
                    db, [REDEEM], out_redeem,
                    {"SIM_WAIT_BARRIER": str(barrier)})

            t = threading.Thread(target=do_redeem)
            t.start()
            procs["shrink"] = run_worker(
                db, [shrink], out_shrink,
                {"SIM_SIGNAL_BARRIER": str(barrier)})
            t.join()

            self.assertEqual(procs["shrink"].returncode, 0, procs["shrink"].stderr)
            self.assertEqual(procs["redeem"].returncode, 0, procs["redeem"].stderr)
            self.assertEqual(read_out(out_shrink)[0]["invalidated"], 1)
            redeem_result = read_out(out_redeem)[0]
            self.assertEqual(redeem_result["status"], "error")
            self.assertEqual(redeem_result["error"], "E_CREDENTIAL_INVALID")
            summary = summary_of(db)
            self.assertEqual(summary["sessions_total"], 0)
            self.assertEqual(summary["credentials"]["invalidated"], 1)

    def test_old_device_callback_arrives_late(self):
        # The callback was sent before the device reset (claim iat < reset)
        # but is processed after it: the frozen device generation no longer
        # matches, so the callback fails and consumes nothing.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "state.db"
            build_db(db, [CHALLENGE])
            barrier = tmp / "reset.barrier"
            reset = {"request_id": "w-reset", "op": "reset_device",
                     "now": 250, "device_id": "d1"}
            out_cb, out_reset = tmp / "cb.json", tmp / "reset.json"
            import threading
            procs = {}

            def do_callback():
                procs["cb"] = run_worker(
                    db, [CALLBACK], out_cb,
                    {"SIM_WAIT_BARRIER": str(barrier)})

            t = threading.Thread(target=do_callback)
            t.start()
            procs["reset"] = run_worker(
                db, [reset], out_reset,
                {"SIM_SIGNAL_BARRIER": str(barrier)})
            t.join()

            self.assertEqual(procs["reset"].returncode, 0, procs["reset"].stderr)
            self.assertEqual(procs["cb"].returncode, 0, procs["cb"].stderr)
            self.assertEqual(read_out(out_reset)[0]["generation"], 2)
            cb_result = read_out(out_cb)[0]
            self.assertEqual(cb_result["status"], "error")
            self.assertEqual(cb_result["error"], "E_DEVICE_GENERATION")
            summary = summary_of(db)
            self.assertEqual(summary["claims_consumed"], 0)   # nothing consumed
            self.assertEqual(summary["credentials"],
                             {"issued": 0, "consumed": 0, "invalidated": 0})


class TestCrashRecovery(unittest.TestCase):
    def test_kill_after_session_insert_rolls_back(self):
        # Writer dies after inserting the session row but before COMMIT:
        # nothing may survive; the same request can then succeed cleanly.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "state.db"
            build_db(db, [CHALLENGE, CALLBACK])
            out = tmp / "redeem.json"
            proc = run_worker(db, [REDEEM], out,
                              {"SIM_CRASH_AFTER": "session_insert"})
            self.assertEqual(proc.returncode, 3)
            self.assertFalse(out.exists())

            store = Store(str(db))
            self.assertIsNone(store.get_receipt("w-rd"))
            store.close()
            summary = summary_of(db)
            self.assertEqual(summary["sessions_total"], 0)
            self.assertEqual(summary["credentials"],
                             {"issued": 1, "consumed": 0, "invalidated": 0})

            # restart: the same request now completes, exactly once
            proc2 = run_worker(db, [REDEEM], out)
            self.assertEqual(proc2.returncode, 0, proc2.stderr)
            self.assertEqual(read_out(out)[0]["session_id"], "SE-w-rd")
            self.assertEqual(summary_of(db)["sessions_total"], 1)

    def test_kill_after_commit_replays_from_receipt(self):
        # Writer dies after COMMIT but before returning: the receipt is
        # durable, so the same request is replayed without side effects and
        # a different request for the same credential is rejected.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = tmp / "state.db"
            build_db(db, [CHALLENGE, CALLBACK])
            out = tmp / "redeem.json"
            proc = run_worker(db, [REDEEM], out, {"SIM_CRASH_AFTER": "commit"})
            self.assertEqual(proc.returncode, 3)
            self.assertFalse(out.exists())

            store = Store(str(db))
            receipt = store.get_receipt("w-rd")
            store.close()
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["session_id"], "SE-w-rd")
            self.assertEqual(summary_of(db)["sessions_total"], 1)

            # same request id -> answered from the receipt, no new session
            proc2 = run_worker(db, [REDEEM], out)
            self.assertEqual(proc2.returncode, 0, proc2.stderr)
            replayed = read_out(out)[0]
            self.assertTrue(replayed["replayed"])
            self.assertEqual(replayed["session_id"], "SE-w-rd")
            self.assertEqual(summary_of(db)["sessions_total"], 1)

            # different request id, same credential -> consume-once violation
            other = dict(REDEEM, request_id="w-rd-other")
            out_other = tmp / "other.json"
            proc3 = run_worker(db, [other], out_other)
            self.assertEqual(proc3.returncode, 0, proc3.stderr)
            result = read_out(out_other)[0]
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["error"], "E_CREDENTIAL_CONSUMED")
            self.assertEqual(summary_of(db)["sessions_total"], 1)


if __name__ == "__main__":
    unittest.main()
