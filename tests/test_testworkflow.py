"""Regression guards for immutable evidence and truthful test reporting."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/testworkflow" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class TestEvidenceReport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "evidence"
        self.root.mkdir()
        self.output = Path(self.temp.name) / "report"
        self.report = load("report")

    def suite(self, name="hosted", status="passed", commit=SHA, artifacts=None):
        directory = self.root / name
        directory.mkdir(exist_ok=True)
        (directory / "results.json").write_text(json.dumps({"schema_version": 1, "suite": name,
            "source_commit": commit, "status": status, "checks": [{"name": "fixture", "status": "passed", "detail": "fixture evidence"}], "measurements": [],
            "environment": {}, "artifacts": artifacts or [], "limitations": []}))
        return directory

    def collect(self, required=("hosted",)):
        return self.report.collect(self.root, self.output, SHA, list(required))

    def test_absent_requested_device_cannot_pass(self):
        self.suite()
        result = self.collect(("hosted", "router131"))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(next(s for s in result["suites"] if s["suite"] == "router131")["status"], "blocked")

    def test_optional_device_is_explicitly_skipped(self):
        self.suite()
        result = self.collect()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(next(s for s in result["suites"] if s["suite"] == "router131")["status"], "skipped")

    def test_requested_stage_cannot_be_skipped(self):
        self.suite(status="skipped")
        self.assertEqual(self.collect()["status"], "failed")

    def test_bundle_with_missing_binary_fails(self):
        self.suite()
        (self.root / "bundle.json").write_text(json.dumps({"source_commit": SHA, "goarch": "arm64",
            "files": {"mosdns-minimal": {"bytes": 4, "sha256": "0" * 64, "source_commit": SHA}}}))
        self.assertEqual(self.collect()["status"], "failed")

    def test_wrong_source_and_duplicate_suite_fail(self):
        self.suite(commit="b" * 40)
        self.assertEqual(self.collect()["status"], "failed")
        other = self.root / "duplicate"
        other.mkdir()
        (other / "results.json").write_text((self.root / "hosted/results.json").read_text())
        self.assertEqual(self.collect()["status"], "failed")

    def test_artifact_traversal_and_symlink_are_rejected(self):
        outside = Path(self.temp.name) / "private"
        outside.write_text("must not appear")
        directory = self.suite(artifacts=["../private"])
        self.assertEqual(self.collect()["status"], "failed")
        (directory / "symlink").symlink_to(outside)
        self.assertIsNone(self.report.safe_file(self.root, "hosted/symlink"))

    def test_truncated_go_log_fails_even_with_passed_suite(self):
        directory = self.suite()
        (directory / "go-test.jsonl").write_text(json.dumps({"Action": "start", "Package": "test/pkg"}) + "\n")
        self.assertEqual(self.collect()["status"], "failed")

    def test_raw_file_is_hashed_and_safe_for_html(self):
        directory = self.suite(artifacts=["raw.log"])
        (directory / "raw.log").write_text("<script>alert(1)</script>")
        result = self.collect()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(any(a["sha256"] for a in result["artifacts"] if a["path"].endswith("raw.log")))
        self.assertNotIn("secret-value", json.dumps(self.report.clean({"token": "secret-value"})))

    def test_calibration_cannot_replace_a_formal_baseline(self):
        base = {"kind": "controlled_dns", "profile": "baseline", "round": 1, "cache": "cold", "network": "udp", "concurrency": 1, "queries": 100, "seconds": 3, "qps": 33.3, "errors": 0, "p95_ms": 1}
        profile = dict(base, profile="minimal", qps=66.6, seconds=1.5)
        calibration = dict(base, kind="calibration", excluded_from_formal=True, qps=100)
        rows = self.report.performance_comparisons([calibration, profile])
        self.assertFalse(rows)
        rows = self.report.performance_comparisons([base, profile])
        self.assertEqual(len(rows), 1)
        self.assertIn("not compared", rows[0][7])


class TestHostedMeasurement(unittest.TestCase):
    def setUp(self):
        self.lab = load("hosted_lab")
        self.row = {"queries": 20, "concurrency": 4, "active_workers": 4, "errors": 0,
            "error_types": {}, "rcodes": {"0": 20}, "seconds": 2, "qps": 10,
            "p50_ms": 1, "p95_ms": 2, "p99_ms": 3, "max_ms": 4, "mean_ms": 2}

    def test_partial_concurrency_is_not_a_valid_sample(self):
        self.row["active_workers"] = 3
        with self.assertRaises(RuntimeError):
            self.lab.validated_measurement(self.row, 20, 4)

    def test_wrong_qps_denominator_is_rejected(self):
        self.row["qps"] = 20
        with self.assertRaises(RuntimeError):
            self.lab.validated_measurement(self.row, 20, 4)

    def test_failed_queries_do_not_enter_latency_comparison(self):
        self.row["errors"] = 1
        with self.assertRaises(RuntimeError):
            self.lab.validated_measurement(self.row, 20, 4)

    def test_nxdomain_requires_correct_code_and_matching_id(self):
        text = json.dumps({"id_ok": True, "rcode": 3, "truncated": False, "answers": []})
        self.lab.parse_probe(text, expected_rcode=3)
        with self.assertRaises(RuntimeError):
            self.lab.parse_probe(text.replace('true', 'false'), expected_rcode=3)


class TestValidationExit(unittest.TestCase):
    def test_failed_compiler_status_retained_as_failure(self):
        module = load("validate")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            args = ["validate.py", "--profile", "minimal", "--commit", SHA, "--output", str(output)]
            with mock.patch.object(sys, "argv", args), mock.patch.object(module.subprocess, "check_output", return_value=SHA + "\n"), \
                 mock.patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                self.assertEqual(module.main(), 1)
            result = json.loads((output / "results.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["source_commit"], SHA)
            with mock.patch.object(sys, "argv", args):
                with self.assertRaises(FileExistsError):
                    module.main()


if __name__ == "__main__":
    unittest.main()
