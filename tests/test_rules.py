"""Rule tests: run cases.json through the SQLite-backed implementation and
assert the concrete expected outcome of every single operation, plus the
final summary.  Also covers the CLI contract and the two-phase restart
(challenge+callback in one process, redeem in a fresh process)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))

sys.path.insert(0, str(ROOT))
from solution.runner import run_cases  # noqa: E402

# Concrete expected (status, error) for every operation in cases.json, in
# order.  rd-1 appears twice: the second submission must be answered from the
# durable receipt.
EXPECTED = [
    ("ch-1", "ok", None), ("cb-1", "ok", None), ("rd-1", "ok", None),
    ("rd-1", "ok", None),                       # replayed receipt
    ("ch-2", "ok", None), ("cb-2", "ok", None), ("rd-2", "ok", None),
    ("ch-3", "ok", None), ("cb-3", "ok", None), ("rd-3", "ok", None),
    ("ch-4", "ok", None), ("cb-4", "ok", None),
    ("revoke-subject-1", "ok", None),
    ("rd-4", "error", "E_CREDENTIAL_INVALID"),  # subject revoked -> sticky
    ("rd-4-retry", "error", "E_CREDENTIAL_INVALID"),  # cannot be revived
    ("ch-5", "ok", None), ("cb-5", "ok", None), ("rd-5", "ok", None),
    ("ch-6", "ok", None),
    ("cb-6", "error", "E_CHALLENGE_MISMATCH"),  # valid claim, wrong challenge
    ("ch-7", "error", "E_NONCE_REUSED"),        # same nonce, same client
    ("ch-8", "ok", None),
    ("cb-8", "error", "E_CHALLENGE_EXPIRED"),   # exactly at expiry
    ("ch-9", "ok", None),
    ("cb-9", "error", "E_CLAIM_TIME"),          # claim exactly at its exp
    ("ch-10", "ok", None), ("cb-10", "ok", None),
    ("rd-10", "error", "E_CHALLENGE_EXPIRED"),  # redeem exactly at expiry
    ("ch-11", "ok", None), ("cb-11", "ok", None),
    ("rd-11-bad", "error", "E_VERIFIER_MISMATCH"),
    ("rd-11", "ok", None),                      # failed redeem consumed nothing
    ("cb-1-replay", "error", "E_CLAIM_REPLAYED"),
    ("ch-12", "ok", None), ("cb-12", "ok", None),
    ("reset-d2", "ok", None),
    ("rd-12", "error", "E_CREDENTIAL_INVALID"),  # device reset invalidated it
    ("ch-13", "ok", None), ("cb-13", "ok", None),
    ("ch-14", "ok", None), ("cb-14", "ok", None),
    ("ch-23", "ok", None), ("cb-23", "ok", None), ("rd-23", "ok", None),
    ("shrink-c1", "ok", None),
    ("rd-13", "error", "E_CREDENTIAL_INVALID"),  # shrunk away
    ("rd-14", "ok", None),                       # [read] survives the shrink
    ("ch-15", "ok", None), ("cb-15", "ok", None),
    ("revoke-p4", "ok", None),
    ("rd-15", "error", "E_CREDENTIAL_INVALID"),
    ("ch-16", "error", "E_PROVIDER_REVOKED"),
    ("ch-17", "ok", None), ("cb-17", "ok", None),
    ("revoke-c2", "ok", None),
    ("rd-17", "error", "E_CREDENTIAL_INVALID"),
    ("ch-18", "error", "E_CLIENT_REVOKED"),
    ("ch-19", "error", "E_CALLBACK_NOT_REGISTERED"),  # trailing slash
    ("ch-20", "error", "E_SCOPE_NOT_GRANTED"),
    ("ch-21", "error", "E_EXPIRY_PAST"),
    ("ch-22", "ok", None),
    ("cb-22", "error", "E_ISSUER_MISMATCH"),
    ("cb-22b", "error", "E_AUDIENCE_MISMATCH"),
    ("cb-22c", "error", "E_SUBJECT_INVALID"),
    ("cb-22d", "ok", None),                      # failures left challenge pending
    ("rd-22-badscopes", "error", "E_SCOPE_MISMATCH"),
    ("rd-22-badcb", "error", "E_CALLBACK_MISMATCH"),
    ("rd-22-badclient", "error", "E_CLIENT_MISMATCH"),
    ("rd-22", "ok", None),
    ("rd-unknown", "error", "E_CREDENTIAL_UNKNOWN"),
    ("rd-1-double", "error", "E_CREDENTIAL_CONSUMED"),
    ("ch-badtenant", "error", "E_TENANT_UNKNOWN"),
    ("ch-badprovider", "error", "E_PROVIDER_UNKNOWN"),
    ("ch-badclient", "error", "E_CLIENT_UNKNOWN"),
    ("ch-baddevice", "error", "E_DEVICE_UNKNOWN"),
    ("cb-badchallenge", "error", "E_CHALLENGE_UNKNOWN"),
    ("ch-24", "ok", None),
    ("cb-24", "error", "E_SUBJECT_REVOKED"),
    ("ch-25", "ok", None),
    ("cb-25", "error", "E_CLAIM_TIME"),          # iat in the future
]

EXPECTED_SUMMARY = {
    "sessions_total": 8,
    "sessions": ["SE-rd-1", "SE-rd-11", "SE-rd-14", "SE-rd-2", "SE-rd-22",
                 "SE-rd-23", "SE-rd-3", "SE-rd-5"],
    "credentials": {"issued": 1, "consumed": 8, "invalidated": 5},
    "claims_consumed": 14,
    "challenges": {"pending": 5, "callback_done": 6, "redeemed": 8},
    "devices": {"d1": 5, "d2": 3, "d3": 1},
}


class TestCasesFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = run_cases(CASES)

    def test_every_operation_outcome(self):
        results = self.out["results"]
        self.assertEqual(len(results), len(EXPECTED))
        for result, (rid, status, error) in zip(results, EXPECTED):
            with self.subTest(request_id=rid):
                self.assertEqual(result["request_id"], rid)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["error"], error)

    def test_replayed_receipt(self):
        replayed = self.out["results"][3]
        self.assertEqual(replayed["request_id"], "rd-1")
        self.assertTrue(replayed["replayed"])
        self.assertEqual(replayed["session_id"], "SE-rd-1")

    def test_invalidation_counts(self):
        by_id = {r["request_id"]: r for r in self.out["results"]}
        self.assertEqual(by_id["revoke-subject-1"]["invalidated"], 1)
        self.assertEqual(by_id["reset-d2"]["invalidated"], 1)
        self.assertEqual(by_id["reset-d2"]["generation"], 3)
        self.assertEqual(by_id["shrink-c1"]["invalidated"], 1)
        self.assertEqual(by_id["revoke-p4"]["invalidated"], 1)
        self.assertEqual(by_id["revoke-c2"]["invalidated"], 1)

    def test_summary(self):
        self.assertEqual(self.out["summary"], EXPECTED_SUMMARY)

    def test_subject_independence(self):
        # alice exists as three independent subjects (t1/p1, t1/p2, t2/p3):
        # revoking t1/p1/alice must not touch the other two sessions.
        sessions = self.out["summary"]["sessions"]
        self.assertIn("SE-rd-2", sessions)   # alice via p2
        self.assertIn("SE-rd-3", sessions)   # alice via t2/p3
        self.assertIn("SE-rd-5", sessions)   # alice via p2 after the revocation


class TestCliContract(unittest.TestCase):
    def test_cli_module_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "result.json"
            proc = subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", "cases.json", "--output", str(out_path)],
                cwd=ROOT, capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("80 operations", proc.stdout)
            out = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(out["summary"], EXPECTED_SUMMARY)
            self.assertEqual(len(out["results"]), 80)

    def test_two_phase_restart(self):
        # Phase A (challenge+callback) and phase B (redeem) run as two
        # independent processes against the same database file.
        mini = {
            "setup": {
                "tenants": [{"tenant_id": "t1"}],
                "providers": [{"provider_id": "p1", "tenant_id": "t1",
                               "issuer": "https://idp.example"}],
                "clients": [{"client_id": "c1", "tenant_id": "t1",
                             "callbacks": ["https://app.example/cb"],
                             "scopes": ["read"]}],
                "devices": [{"device_id": "d1", "tenant_id": "t1", "generation": 1}],
            },
            "operations": [
                {"request_id": "a-ch", "op": "challenge", "now": 100,
                 "tenant_id": "t1", "provider_id": "p1", "client_id": "c1",
                 "device_id": "d1", "callback": "https://app.example/cb",
                 "scopes": ["read"], "verifier": "v", "nonce": "N1",
                 "expires_at": 900},
                {"request_id": "a-cb", "op": "callback", "now": 200,
                 "challenge_id": "CH-a-ch",
                 "claim": {"claim_id": "CL-A", "challenge_id": "CH-a-ch",
                           "iss": "https://idp.example", "aud": "c1",
                           "sub": "alice", "iat": 150, "exp": 800}},
            ],
        }
        phase_b = {"operations": [
            {"request_id": "a-rd", "op": "redeem", "now": 300,
             "credential_id": "CR-a-cb", "callback": "https://app.example/cb",
             "client_id": "c1", "verifier": "v", "scopes": ["read"]},
        ]}
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.db"
            in_a = Path(tmp) / "a.json"
            in_b = Path(tmp) / "b.json"
            out_a = Path(tmp) / "out_a.json"
            out_b = Path(tmp) / "out_b.json"
            in_a.write_text(json.dumps(mini), encoding="utf-8")
            in_b.write_text(json.dumps(phase_b), encoding="utf-8")
            # first process exits completely before the second starts
            pa = subprocess.run(
                [sys.executable, "-m", "solution", "--input", str(in_a),
                 "--output", str(out_a), "--db", str(db)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(pa.returncode, 0, pa.stderr)
            pb = subprocess.run(
                [sys.executable, "-m", "solution", "--input", str(in_b),
                 "--output", str(out_b), "--db", str(db)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(pb.returncode, 0, pb.stderr)
            res_b = json.loads(out_b.read_text(encoding="utf-8"))
            self.assertEqual(res_b["results"][0]["status"], "ok")
            self.assertEqual(res_b["results"][0]["session_id"], "SE-a-rd")
            self.assertEqual(res_b["summary"]["sessions_total"], 1)


if __name__ == "__main__":
    unittest.main()
