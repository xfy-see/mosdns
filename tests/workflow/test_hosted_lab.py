"""Regression guards for truthful load/probe and nft evidence interpretation."""
import copy
import importlib.util
from pathlib import Path
import unittest

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
