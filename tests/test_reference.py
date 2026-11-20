"""Cross-check the SQLite-backed implementation against the independent
in-memory reference implementation (solution.reference) on the synthetic
inputs, and verify the reference itself rejects corrupted inputs."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from solution import reference  # noqa: E402
from solution.runner import run_cases  # noqa: E402

CASES = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))


class TestReferenceAgreement(unittest.TestCase):
    def test_reference_matches_sqlite_on_cases(self):
        expected = reference.run_cases(CASES)
        actual = run_cases(CASES)
        self.assertEqual(actual["results"], expected["results"])
        self.assertEqual(actual["summary"], expected["summary"])

    def test_reference_is_deterministic_across_runs(self):
        first = run_cases(CASES)
        second = run_cases(CASES)
        self.assertEqual(first, second)

    def test_reference_flags_mutated_input(self):
        # Flip one claim's audience: the reference must disagree with the
        # un-mutated expectation, proving the comparison is not vacuous.
        mutated = json.loads(json.dumps(CASES))
        for op in mutated["operations"]:
            if op["request_id"] == "cb-2":
                op["claim"]["aud"] = "c1"
        out = reference.run_cases(mutated)
        by_id = {r["request_id"]: r for r in out["results"]}
        self.assertEqual(by_id["cb-2"]["status"], "error")
        self.assertEqual(by_id["cb-2"]["error"], "E_AUDIENCE_MISMATCH")
        self.assertEqual(out["summary"]["sessions_total"], 7)


if __name__ == "__main__":
    unittest.main()
