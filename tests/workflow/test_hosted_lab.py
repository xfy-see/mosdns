"""Regression guards for truthful load/probe and nft evidence interpretation."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
from types import SimpleNamespace
import tempfile

MODULE = Path(__file__).resolve().parents[2] / "scripts/testworkflow/hosted_lab.py"
spec = importlib.util.spec_from_file_location("hosted_lab", MODULE)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LoadValidation(unittest.TestCase):
    def setUp(self):
        self.valid = {"queries": 100, "concurrency": 4, "active_workers": 4,
                      "errors": 0, "error_types": {}, "rcodes": {"0": 100},
                      "seconds": 2.0, "qps": 50.0, "p50_ms": .1, "p95_ms": .2,
                      "p99_ms": .3, "max_ms": .4, "mean_ms": .15}

    def test_valid_complete_run(self):
        self.assertEqual(lab.validated_measurement(self.valid, 100, 4), self.valid)

    def test_invalid_measurements_are_rejected(self):
        mutations = {"queries": 99, "concurrency": 3, "active_workers": 3,
                     "errors": 1, "error_types": {"timeout": 1}, "rcodes": {"0": 99, "3": 1},
                     "seconds": 0, "qps": 100, "p50_ms": float("nan"), "p95_ms": .05,
                     "p99_ms": float("inf"), "max_ms": -1}
        for key, value in mutations.items():
            with self.subTest(key=key):
                row = copy.deepcopy(self.valid)
                row[key] = value
                with self.assertRaises(RuntimeError):
                    lab.validated_measurement(row, 100, 4)

    def test_baseline_timeouts_record_success_qps_without_relaxing_default(self):
        row = dict(self.valid, errors=1, error_types={"read udp 127.0.0.1:1234->127.0.0.1:15353: i/o timeout": 1},
                   rcodes={"0": 99}, qps=49.5)
        self.assertEqual(lab.validated_measurement(row, 100, 4, allow_baseline_errors=True), row)
        with self.assertRaises(RuntimeError):
            lab.validated_measurement(row, 100, 4)
        for change in ({"qps": 50}, {"rcodes": {"0": 100}},
                       {"error_types": {"split answer validation failed": 1}},
                       {"error_types": {"read udp 127.0.0.1:1->127.0.0.1:15353: i/o timeout": 2}}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                lab.validated_measurement(dict(row, **change), 100, 4, allow_baseline_errors=True)

    def test_observed_baseline_id_mismatch_class_keeps_strict_optimized_policy(self):
        row = dict(self.valid, errors=3, error_types={"dns: id mismatch": 2,
                   "read tcp 127.0.0.1:1234->127.0.0.1:15353: i/o timeout": 1},
                   rcodes={"0": 97}, qps=48.5)
        self.assertEqual(lab.validated_measurement(row, 100, 4, allow_baseline_errors=True), row)
        with self.assertRaises(RuntimeError):
            lab.validated_measurement(row, 100, 4)
        for error in ("dns: id mismatch (unknown)", "response validation failed", "split answer validation failed"):
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                lab.validated_measurement(dict(row, error_types={error: 3}), 100, 4, allow_baseline_errors=True)


class FailureEvidence(unittest.TestCase):
    def test_validation_failure_retains_sampler_and_cgroup_evidence(self):
        for stop_error in (None, RuntimeError("server cgroup reported OOM")):
            with self.subTest(stop_error=stop_error), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                group = output / "owned-group"
                group.mkdir()
                for name, text in {"memory.peak": "41943040", "memory.events": "oom 1\noom_kill 1",
                                   "cpu.stat": "usage_usec 100", "pids.events": "max 0"}.items():
                    (group / name).write_text(text)
                args = SimpleNamespace(output=output, commit="a" * 40, namespace="mosdns-lab-" + "a" * 32,
                                       baseline=Path("baseline"))
                controller = lab.Lab(args)
                controller.spawn = mock.Mock(return_value=(SimpleNamespace(pid=123), group))
                controller.ready = mock.Mock(side_effect=RuntimeError("response validation failed"))
                controller.stop = mock.Mock(return_value={}, side_effect=stop_error)
                sampler = SimpleNamespace(stop=mock.Mock(return_value={"rss_peak_bytes": 41000000,
                    "hwm_peak_bytes": 42000000, "process_cpu_seconds": 1.0, "samples": []}))
                with mock.patch.object(lab, "ResourceSampler", return_value=sampler):
                    with self.assertRaises(RuntimeError):
                        controller.trial("baseline", "cold", "udp", 4, 3000, "calibration-05-baseline")
                evidence = lab.json.loads((output / "calibration-05-baseline-resources.json").read_text())
                self.assertEqual(evidence["rss_peak_bytes"], 41000000)
                self.assertEqual(evidence["cgroup"]["memory.peak"], "41943040")
                self.assertIn("oom_kill 1", evidence["cgroup"]["memory.events"])
                self.assertEqual(evidence["trial_error"], "response validation failed")
                self.assertEqual(evidence["query_timeout_seconds"], 2)
                if stop_error:
                    self.assertIn("OOM", evidence["cleanup_error"])
                controller.stop.assert_called_once()


class ProbeValidation(unittest.TestCase):
    def test_ipv4_ipv6_and_cached_ttl(self):
        for typ, address in (("A", "223.5.5.5"), ("AAAA", "2400:3200::1")):
            for ttl in (299, 300):
                value = {"id_ok": True, "rcode": 0, "truncated": False, "type": typ,
                         "answers": ["learn.cn-site.test. %d IN %s %s" % (ttl, typ, address)]}
                self.assertEqual(lab.parse_probe(lab.json.dumps(value), address), value)

    def test_error_question_id_ttl_and_type_are_rejected(self):
        base = {"id_ok": True, "rcode": 0, "truncated": False, "type": "A",
                "answers": ["name. 300 IN A 223.5.5.5"]}
        changes = ({"error": "deadline"}, {"id_ok": False}, {"rcode": 2}, {"truncated": True},
                   {"answers": []}, {"answers": ["name. 0 IN A 223.5.5.5"]},
                   {"answers": ["name. 301 IN A 223.5.5.5"]},
                   {"answers": ["name. 300 IN AAAA 223.5.5.5"]},
                   {"answers": ["name. 300 CH A 223.5.5.5"]},
                   {"answers": ["name. 300 IN A 8.8.8.8"]})
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(RuntimeError):
                    lab.parse_probe(lab.json.dumps(dict(base, **change)), "223.5.5.5")

    def test_nxdomain_checked_separately(self):
        value = {"id_ok": True, "rcode": 3, "truncated": False, "answers": [], "type": "A"}
        lab.parse_probe(lab.json.dumps(value), expected_rcode=3)
        with self.assertRaises(RuntimeError):
            lab.parse_probe(lab.json.dumps(value))

    def test_multiple_response_records_are_rejected(self):
        with self.assertRaises(RuntimeError):
            lab.parse_probe("{}\n{}\n")


class NftEvidence(unittest.TestCase):
    def test_empty_and_populated_sets(self):
        document = {"nftables": [{"set": {"table": lab.TABLE, "name": "cn_site4", "elem": ["223.5.5.5"]}},
                                 {"set": {"table": lab.TABLE, "name": "cn_site6"}}]}
        self.assertEqual(lab.nft_elements(document, "cn_site4"), ["223.5.5.5"])
        self.assertEqual(lab.nft_elements(document, "cn_site6"), [])
        with self.assertRaises(RuntimeError):
            lab.nft_elements(document, "missing")

    def test_counter_must_be_unambiguous(self):
        rule = {"rule": {"expr": [{"counter": {"packets": 10, "bytes": 200}}]}}
        self.assertEqual(lab.nft_counter({"nftables": [rule]}), 10)
        for document in ({"nftables": []}, {"nftables": [rule, rule]}):
            with self.assertRaises(RuntimeError):
                lab.nft_counter(document)


if __name__ == "__main__":
    unittest.main()
