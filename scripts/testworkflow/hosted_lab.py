#!/usr/bin/env python3
"""Private Linux DNS lab: fixed workloads, real nft sets, immutable raw logs.

The supplied binaries are built by CI. This script never invokes Go and never
contacts public DNS, writes host routes, or edits the host nftables ruleset.
"""

import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

DOMAIN_COUNT = 111361
PROFILES = ("baseline", "full", "minimal")
SERVER = "127.0.0.1:15353"
TABLE = "mosdns_lab"
QUERIES = (
    "www.cn-site.test A", "www.cn-site.test AAAA",
    "cdn.cn-site.test A", "cdn.cn-site.test AAAA",
    "www.foreign.test A", "www.foreign.test AAAA",
    "cdn.foreign.test A", "cdn.foreign.test AAAA",
)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def cold_query_prefix(namespace, label):
    # Each paired profile starts a fresh server, so use the same exact DNS names
    # in every profile of this cell. Hash the namespace/label seed: concatenating
    # them directly would exceed DNS's 63-byte label limit at large query N.
    shared_label = re.sub(r"-(?:baseline|full|minimal)$", "", label)
    basis = namespace + "-" + shared_label
    return "q" + hashlib.sha256(basis.encode("ascii")).hexdigest()[:24] + "-", basis


def validated_measurement(value, count, concurrency, *, allow_baseline_errors=False):
    """Reject partial/invalid runs, including workers that never acquired work."""
    require(isinstance(value, dict), "load output must be a JSON object")
    require(value.get("queries") == count, "load query count differs")
    require(value.get("concurrency") == concurrency, "load concurrency differs")
    require(value.get("active_workers") == concurrency, "requested concurrency was not exercised")
    errors = value.get("errors")
    error_types = value.get("error_types")
    if allow_baseline_errors:
        require(type(errors) is int and 0 <= errors <= count and isinstance(error_types, dict),
                "invalid DNS error accounting")
        require(all((key == "dns: id mismatch" or re.fullmatch(r"read (?:udp|tcp) .+: i/o timeout", key))
                    and type(number) is int and number > 0 for key, number in error_types.items())
                and sum(error_types.values()) == errors,
                "only recorded old-baseline read timeouts/ID mismatches may continue")
    else:
        require(errors == 0 and error_types == {}, "DNS response validation failed")
    successes = count - errors
    require(value.get("rcodes") == ({"0": successes} if successes else {}), "unexpected DNS response codes")
    for key in ("seconds", "qps", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms"):
        require(type(value.get(key)) in (int, float) and math.isfinite(value[key]) and value[key] >= 0,
                "invalid numeric metric: " + key)
    require(value["seconds"] > 0, "nonpositive measured duration")
    require(math.isclose(value["qps"], successes / value["seconds"], rel_tol=1e-6), "QPS denominator differs")
    require(value["p50_ms"] <= value["p95_ms"] <= value["p99_ms"] <= value["max_ms"],
            "latency quantiles are not ordered")
    return value


def parse_probe(text, expected_ip=None, expected_rcode=0):
    values = [json.loads(line) for line in text.splitlines() if line.strip()]
    require(len(values) == 1, "probe returned an unexpected number of responses")
    value = values[0]
    require(not value.get("error") and value.get("id_ok") is True, "probe response/ID invalid")
    require(value.get("rcode") == expected_rcode and value.get("truncated") is False,
            "probe response code or truncation invalid")
    if expected_ip is not None:
        answers = value.get("answers", [])
        require(len(answers) == 1, "probe answer count differs")
        fields = answers[0].split()
        require(len(fields) == 5 and fields[-1] == expected_ip and fields[2] == "IN",
                "probe address/class differs")
        require(fields[3] == value["type"] and 0 < int(fields[1]) <= 300,
                "probe answer type/TTL invalid")
    return value


def nft_elements(document, set_name):
    for item in document.get("nftables", []):
        value = item.get("set", {})
        if value.get("name") == set_name and value.get("table") == TABLE:
            return value.get("elem", [])
    raise RuntimeError("nft set missing: " + set_name)


def nft_counter(document):
    counters = [expr["counter"]["packets"]
                for item in document.get("nftables", [])
                for expr in item.get("rule", {}).get("expr", []) if "counter" in expr]
    require(len(counters) == 1, "upstream packet counter missing or ambiguous")
    return counters[0]


def config(rule_path, *, nft=False):
    finalize = []
    if nft:
        finalize.append({"matches": ["qname $cn_site"], "exec":
                         "nftset inet,mosdns_lab,cn_site4,ipv4_addr,32 inet,mosdns_lab,cn_site6,ipv6_addr,128"})
    finalize.append({"exec": "accept"})
    return {"log": {"level": "error"}, "plugins": [
        {"tag": "cn_site", "type": "domain_set", "args": {"files": [str(rule_path)]}},
        {"tag": "cached", "type": "cache", "args": {"size": 1024, "lazy_cache_ttl": 0}},
        {"tag": "domestic", "type": "forward", "args": {"upstreams": [{"addr": "127.0.0.1:15351"}]}},
        {"tag": "foreign", "type": "forward", "args": {"upstreams": [{"addr": "127.0.0.1:15352"}]}},
        {"tag": "finalize", "type": "sequence", "args": finalize},
        {"tag": "resolve_domestic", "type": "sequence", "args": [
            {"exec": "$domestic"}, {"exec": "goto finalize"}]},
        {"tag": "main", "type": "sequence", "args": [
            {"exec": "$cached"}, {"matches": ["has_resp"], "exec": "goto finalize"},
            {"matches": ["qname $cn_site"], "exec": "goto resolve_domestic"},
            {"exec": "$foreign"}, {"exec": "goto finalize"}]},
        {"type": "udp_server", "args": {"listen": SERVER, "entry": "main"}},
        {"type": "tcp_server", "args": {"listen": SERVER, "entry": "main"}},
    ]}


class ResourceSampler:
    def __init__(self, pid):
        self.pid = pid
        self.samples = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def sample(self):
        while not self.stop_event.is_set():
            try:
                fields = Path("/proc/%d/stat" % self.pid).read_text().rsplit(")", 1)[1].split()
                status = Path("/proc/%d/status" % self.pid).read_text()
                memory = {m.group(1): int(m.group(2)) * 1024
                          for m in re.finditer(r"^(VmRSS|VmHWM):\s+(\d+) kB$", status, re.M)}
                self.samples.append({"monotonic": time.monotonic(),
                                     "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                                     **memory})
            except (OSError, ValueError, IndexError):
                pass
            self.stop_event.wait(.1)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=2)
        return {"sampling_interval_ms": 100,
                "rss_peak_bytes": max((x.get("VmRSS", 0) for x in self.samples), default=0),
                "hwm_peak_bytes": max((x.get("VmHWM", 0) for x in self.samples), default=0),
                "process_cpu_seconds": max((x["cpu_seconds"] for x in self.samples), default=0),
                "samples": self.samples}


class Lab:
    def __init__(self, args):
        self.args = args
        self.output = args.output
        self.index = 0
        self.processes = []
        self.cgroups = []
        self.result = {"schema_version": 1, "suite": "hosted", "status": "failed",
                       "source_commit": args.commit, "checks": [], "measurements": [],
                       "environment": {}, "artifacts": [], "limitations": [
                           "The 111361-line CN-site fixture is synthetic; real CN lists and public DNS are not tested.",
                           "Loopback namespace results include load-client and mock-upstream scheduling on a shared CI host.",
                           "The performance matrix has no nft writes; separate nft checks cover insertion and cache rebuilding, not expiry or kernel commit latency.",
                           "This stage does not establish router/WireGuard routing, public website performance, or long-term stability.",
                           "Only two descriptive alternating rounds are collected; these are not statistical significance estimates.",
                           "Per-process CPU accounting includes startup and warmup; RSS/HWM are sampled every 100 ms.",
                       ]}

    def save(self):
        write_json(self.output / "results.json", self.result)

    def check(self, name, detail):
        self.result["checks"].append({"name": name, "status": "passed", "detail": detail})
        self.save()

    def command(self, argv, name, timeout=20):
        self.index += 1
        prefix = self.output / ("%03d-%s" % (self.index, name))
        write_json(Path(str(prefix) + ".command.json"), {"argv": list(map(str, argv)), "timeout_seconds": timeout})
        with Path(str(prefix) + ".stdout").open("w") as stdout, Path(str(prefix) + ".stderr").open("w") as stderr:
            proc = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
                raise RuntimeError("command deadline exceeded: " + name)
        require(code == 0, "command failed (%d): %s; see raw logs" % (code, name))
        return Path(str(prefix) + ".stdout").read_text()

    def spawn(self, argv, name, limited=False):
        self.index += 1
        prefix = self.output / ("%03d-%s" % (self.index, name))
        stdout = Path(str(prefix) + ".stdout").open("w")
        stderr = Path(str(prefix) + ".stderr").open("w")
        cgroup = None
        if limited and self.result["environment"].get("cgroup_limits_available"):
            cgroup = Path("/sys/fs/cgroup") / (self.args.namespace + "-%03d" % self.index)
            cgroup.mkdir()
            self.cgroups.append(cgroup)
            for key, value in {"memory.max": "67108864", "memory.swap.max": "0", "pids.max": "64",
                               "cpu.max": "200000 100000"}.items():
                (cgroup / key).write_text(value)

        def enter_cgroup():
            if cgroup is not None:
                (cgroup / "cgroup.procs").write_text(str(os.getpid()))

        env = dict(os.environ, GOMAXPROCS="2", GOMEMLIMIT="48MiB")
        write_json(Path(str(prefix) + ".command.json"), {"argv": list(map(str, argv)),
                   "GOMAXPROCS": "2", "GOMEMLIMIT": "48MiB", "cgroup": str(cgroup) if cgroup else None})
        try:
            proc = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr, env=env,
                                    start_new_session=True, preexec_fn=enter_cgroup if cgroup else None)
        finally:
            stdout.close()
            stderr.close()
        self.processes.append(proc)
        return proc, cgroup

    def stop(self, proc, cgroup=None):
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
                raise RuntimeError("server failed to stop within five seconds")
        self.processes.remove(proc)
        resources = {}
        if cgroup:
            for file in ("memory.peak", "memory.events", "cpu.stat", "pids.events"):
                resources[file] = (cgroup / file).read_text().strip()
            cgroup.rmdir()
            self.cgroups.remove(cgroup)
            events = dict(line.split() for line in resources["memory.events"].splitlines())
            require(int(events.get("oom", 0)) == 0 and int(events.get("oom_kill", 0)) == 0,
                    "server cgroup reported OOM")
        return resources

    def ready(self, proc, address=SERVER):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(proc.poll() is None, "server exited before readiness")
            try:
                text = self.command([self.args.dnsbench, "-mode", "probe", "-addr", address,
                                     "-names", "ready.cn-site.test", "-timeout", "200ms"], "readiness", timeout=2)
                parse_probe(text, "223.5.5.5")
                return
            except RuntimeError:
                time.sleep(.1)
        raise RuntimeError("DNS readiness deadline exceeded")

    def probe(self, name, typ, net="udp", expected_ip=None, expected_rcode=0):
        text = self.command([self.args.dnsbench, "-mode", "probe", "-addr", SERVER,
                             "-names", name + " " + typ, "-net", net, "-timeout", "1s"], "probe")
        return parse_probe(text, expected_ip, expected_rcode)

    def nft(self, *args):
        return self.command(["nft", *args], "nft")

    def nft_snapshot(self):
        return json.loads(self.nft("-j", "list", "table", "inet", TABLE))

    def nft_regression(self, profile):
        nft_file = self.output / "nft-rules.nft"
        if not nft_file.exists():
            nft_file.write_text("table inet mosdns_lab {\n"
                                " set cn_site4 { type ipv4_addr; }\n"
                                " set cn_site6 { type ipv6_addr; }\n"
                                " chain count_upstream { type filter hook input priority 0; policy accept; "
                                "udp dport 15351 counter; }\n}\n")
        self.nft("-f", nft_file)
        proc, group = self.spawn([getattr(self.args, profile), "start", "-c", self.output / "nft.json"],
                                 profile + "-nft", limited=True)
        timings = []
        try:
            self.ready(proc)
            # Readiness created one element. Start every assertion from empty
            # owned sets while preserving the upstream counter.
            self.nft("flush", "set", "inet", TABLE, "cn_site4")
            self.nft("flush", "set", "inet", TABLE, "cn_site6")
            for typ, address, set_name in (("A", "223.5.5.5", "cn_site4"),
                                           ("AAAA", "2400:3200::1", "cn_site6")):
                before = nft_counter(self.nft_snapshot())
                started = time.monotonic()
                self.probe("learn.cn-site.test", typ, expected_ip=address)
                after = self.nft_snapshot()
                require(address in nft_elements(after, set_name), "cold answer was not written to nft set")
                require(nft_counter(after) > before, "cold query did not contact its controlled upstream")
                timings.append({"operation": "cold_add", "type": typ,
                                "query_plus_snapshot_ms": (time.monotonic() - started) * 1000})
                self.nft("flush", "set", "inet", TABLE, set_name)
                before = nft_counter(self.nft_snapshot())
                for net in ("udp", "tcp"):
                    started = time.monotonic()
                    self.probe("learn.cn-site.test", typ, net, expected_ip=address)
                    snapshot = self.nft_snapshot()
                    require(address in nft_elements(snapshot, set_name), "cached answer failed to rebuild nft set")
                    require(nft_counter(snapshot) == before, "cached answer contacted the upstream")
                    timings.append({"operation": "cached_rebuild", "type": typ, "network": net,
                                    "query_plus_snapshot_ms": (time.monotonic() - started) * 1000})
                    self.nft("flush", "set", "inet", TABLE, set_name)
            self.probe("foreign.test", "A", expected_ip="8.8.8.8")
            require(nft_elements(self.nft_snapshot(), "cn_site4") == [], "foreign answer entered CN-site set")
            self.probe("absent.nxdomain.test", "A", expected_rcode=3)
            write_json(self.output / (profile + "-nft-timings.json"), timings)
            self.check(profile + "-nft-A-AAAA-cache-rebuild",
                       {"timings": timings, "upstream_counter_verified": True,
                        "timing_scope": "DNS query plus nft userspace snapshot, not kernel commit latency"})
        finally:
            self.stop(proc, group)
            self.nft("delete", "table", "inet", TABLE)

    def trial(self, profile, mode, network, concurrency, count, label):
        print("%s %s %s %s c=%d n=%d" % (label, profile, mode, network, concurrency, count), flush=True)
        proc, group = self.spawn([getattr(self.args, profile), "start", "-c", self.output / "benchmark.json"],
                                 label + "-" + profile, limited=True)
        sampler = ResourceSampler(proc.pid)
        value = None
        resources = None
        trial_error = None
        try:
            self.ready(proc)
            if mode == "hot":
                # Probe every exact A/AAAA key before starting the timed load.
                self.command([self.args.dnsbench, "-mode", "probe", "-addr", SERVER,
                              "-file", self.output / "queries.txt", "-timeout", "2s"], "warmup")
            argv = [self.args.dnsbench, "-mode", "load", "-addr", SERVER,
                    "-file", self.output / "queries.txt", "-net", network,
                    "-n", str(count), "-c", str(concurrency), "-timeout", "2s", "-expect-mock"]
            prefix, prefix_basis = cold_query_prefix(self.args.namespace, label)
            if mode == "cold":
                argv += ["-unique", "-prefix", prefix]
            value = validated_measurement(json.loads(self.command(argv, "load-" + label, timeout=180)),
                                          count, concurrency, allow_baseline_errors=profile == "baseline")
            require(proc.poll() is None, "server exited during measurement")
        except Exception as exc:
            trial_error = str(exc)
            raise
        finally:
            resources = sampler.stop()
            resources["trial_error"] = trial_error
            resources["query_timeout_seconds"] = 2
            # Snapshot before stop(): even its OOM/cleanup assertion may raise.
            resources["cgroup"] = {}
            if group:
                for file in ("memory.peak", "memory.events", "cpu.stat", "pids.events"):
                    try:
                        resources["cgroup"][file] = (group / file).read_text().strip()
                    except OSError as exc:
                        resources["cgroup"][file] = "read failed: " + str(exc)
            try:
                resources["cgroup"].update(self.stop(proc, group))
            except Exception as exc:
                resources["cleanup_error"] = str(exc)
                raise
            finally:
                write_json(self.output / (label + "-resources.json"), resources)
        return {"profile": profile, "cache": mode, **value,
                "status": "failed" if value["errors"] else "passed",
                "resources": {k: v for k, v in resources.items() if k != "samples"},
                "rate_comparison_valid": value["seconds"] >= 2 and value["errors"] == 0,
                "query_timeout_seconds": 2,
                "cold_query_prefix": prefix if mode == "cold" else None,
                "cold_query_prefix_basis": prefix_basis if mode == "cold" else None,
                "nft_writes_enabled": False}

    def run(self):
        require(platform.system() == "Linux" and os.geteuid() == 0, "Linux root is required")
        host_namespace = os.environ.get("MOSDNS_LAB_HOST_NS")
        require(host_namespace and os.readlink("/proc/self/ns/net") != host_namespace,
                "controller must run in the owned network namespace")
        env = self.result["environment"]
        env.update({"namespace": self.args.namespace, "kernel": platform.release(),
                    "architecture": platform.machine(), "GOMAXPROCS": 2, "GOMEMLIMIT": "48MiB",
                    "memory_max_bytes": 67108864, "pids_max": 64, "cpu_quota": "2 CPUs, no affinity",
                    "fixture_kind": "synthetic", "domain_count": DOMAIN_COUNT,
                    "query_timeout_seconds": 2,
                    "baseline_error_collection_policy": "Collect read UDP/TCP i/o timeouts and exact dns: id mismatch as failed noncomparable rows; suite remains failed",
                    "baseline_commit": self.args.baseline_commit,
                    "binaries": {name: {"sha256": sha256(getattr(self.args, name)),
                                         "size_bytes": getattr(self.args, name).stat().st_size}
                                 for name in (*PROFILES, "dnsbench")}})
        root = Path("/sys/fs/cgroup")
        controls = (root / "cgroup.subtree_control").read_text().split() if (root / "cgroup.subtree_control").exists() else []
        env["cgroup_limits_available"] = all(x in controls for x in ("cpu", "memory", "pids"))
        if not env["cgroup_limits_available"]:
            self.result["limitations"].append("Cgroup controllers were not already delegated: no cgroup hard limits applied; GOMEMLIMIT is a soft limit.")
            for key in ("memory_max_bytes", "pids_max", "cpu_quota"):
                env[key] = None
        else:
            self.result["limitations"].append("Hosted servers use a 64 MiB cgroup and 48 MiB GOMEMLIMIT, differing from the historical router's 32 MiB/20 MiB limits.")
        rule_path = self.output / "synthetic-cn-site.txt"
        with rule_path.open("x") as stream:
            stream.write("domain:cn-site.test\n")
            for i in range(DOMAIN_COUNT - 1):
                stream.write("full:d%06d.synthetic-cn.test\n" % i)
        (self.output / "queries.txt").write_text("\n".join(QUERIES) + "\n")
        env["cn_site_sha256"] = sha256(rule_path)
        env["queries_sha256"] = sha256(self.output / "queries.txt")
        write_json(self.output / "benchmark.json", config(rule_path))
        write_json(self.output / "nft.json", config(rule_path, nft=True))
        env["benchmark_config_sha256"] = sha256(self.output / "benchmark.json")
        env["nft_config_sha256"] = sha256(self.output / "nft.json")
        for profile in PROFILES:
            env["binaries"][profile]["version"] = self.command([getattr(self.args, profile), "version"], "version").strip()
            expected_commit = self.args.baseline_commit if profile == "baseline" else self.args.commit
            if expected_commit != "unrecorded":
                require(expected_commit in env["binaries"][profile]["version"],
                        profile + " executable version does not contain its expected source SHA")
        self.save()
        for branch, port in (("cn", 15351), ("foreign", 15352)):
            proc, _ = self.spawn([self.args.dnsbench, "-mode", "mock", "-addr", "127.0.0.1:%d" % port,
                                  "-branch", branch], "mock-" + branch)
            if branch == "cn":
                self.ready(proc, "127.0.0.1:%d" % port)
            else:
                deadline = time.monotonic() + 20
                while True:
                    require(proc.poll() is None, "foreign mock exited before readiness")
                    text = self.command([self.args.dnsbench, "-mode", "probe", "-addr", "127.0.0.1:15352",
                                         "-names", "foreign.test", "-timeout", "200ms"], "mock-readiness")
                    try:
                        parse_probe(text, "8.8.8.8")
                        break
                    except RuntimeError:
                        require(time.monotonic() < deadline, "foreign upstream readiness timed out")
                        time.sleep(.1)
        self.check("environment-deployed", {"namespace": self.args.namespace, "external_network": False})
        for profile in PROFILES:
            self.nft_regression(profile)
        cells = list(itertools.product(("hot", "cold"), ("udp", "tcp"), (1, 4)))
        counts = {}
        calibrations = []
        write_json(self.output / "calibrations.json", calibrations)
        for cell_index, (mode, network, concurrency) in enumerate(cells):
            if self.args.requests:
                counts[(mode, network, concurrency)] = self.args.requests
                continue
            qps = []
            for profile in PROFILES:
                value = self.trial(profile, mode, network, concurrency, 3000,
                                   "calibration-%02d-%s" % (cell_index, profile))
                calibrations.append(value)
                write_json(self.output / "calibrations.json", calibrations)
                qps.append(value["qps"])
            # Fix one query count for every paired profile/round in this cell.
            counts[(mode, network, concurrency)] = min(2000000, max(10000, math.ceil(max(qps) * 3.2)))
        write_json(self.output / "calibrations.json", calibrations)
        write_json(self.output / "frozen-workload.json", {"counts": [{"cache": mode, "network": net,
                    "concurrency": concurrency, "queries": count} for (mode, net, concurrency), count in counts.items()],
                    "cold_prefixes": [{"round": round_index + 1, "cell": cell_index,
                        "prefix": cold_query_prefix(self.args.namespace,
                            "round-%02d-cell-%02d-baseline" % (round_index + 1, cell_index))[0]}
                        for round_index in range(self.args.rounds)
                        for cell_index, (mode, _, _) in enumerate(cells) if mode == "cold"],
                    "rounds": self.args.rounds, "calibration_target_seconds": 3.2,
                    "requests_cap": 2000000, "os_file_cache_dropped": False})
        for round_index in range(self.args.rounds):
            order = PROFILES if round_index % 2 == 0 else tuple(reversed(PROFILES))
            for cell_index, (mode, network, concurrency) in enumerate(cells):
                for profile in order:
                    label = "round-%02d-cell-%02d-%s" % (round_index + 1, cell_index, profile)
                    row = self.trial(profile, mode, network, concurrency,
                                     counts[(mode, network, concurrency)], label)
                    row.update({"round": round_index + 1, "order": list(order), "sample": label})
                    self.result["measurements"].append(row)
                    self.save()
        require(len(self.result["measurements"]) == 24 * self.args.rounds, "matrix incomplete")
        short = [x["sample"] for x in self.result["measurements"] if x["seconds"] < 2]
        error_count = sum(x["errors"] for x in self.result["measurements"])
        calibration_errors = sum(x["errors"] for x in calibrations)
        self.result["checks"].append({"name": "controlled-matrix", "status": "failed" if error_count or calibration_errors else "passed",
            "detail": {"samples": len(self.result["measurements"]), "errors": error_count,
                       "calibration_errors": calibration_errors, "samples_under_two_seconds": short}})
        self.save()
        if short:
            self.result["limitations"].append("Some samples were shorter than two seconds and are excluded from rate comparisons: " + ", ".join(short))
        self.result["status"] = "failed" if error_count or calibration_errors else "passed"

    def cleanup(self):
        for proc in list(self.processes):
            try:
                self.stop(proc)
            except Exception as exc:
                self.result["checks"].append({"name": "process-cleanup", "status": "failed", "detail": str(exc)})
                self.result["status"] = "failed"
        for group in list(self.cgroups):
            try:
                group.rmdir()
            except OSError as exc:
                self.result["checks"].append({"name": "cgroup-cleanup", "status": "failed", "detail": str(exc)})
                self.result["status"] = "failed"
        self.result["artifacts"] = [{"path": str(path.relative_to(self.output)), "sha256": sha256(path),
                                     "size_bytes": path.stat().st_size}
                                    for path in sorted(self.output.iterdir()) if path.is_file() and path.name != "results.json"]
        self.save()


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=lambda x: Path(x).resolve(), required=True)
    for name in (*PROFILES, "dnsbench"):
        parser.add_argument("--" + name, type=lambda x: Path(x).resolve(), required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--baseline-commit", default="unrecorded")
    parser.add_argument("--requests", type=int, default=0, help="0: calibrate fixed per-cell N; explicit N may produce short samples")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--inside-namespace", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--namespace", help=argparse.SUPPRESS)
    args = parser.parse_args()
    parser.error("commit must be a complete Git SHA") if not re.fullmatch(r"[0-9a-f]{40}", args.commit) else None
    parser.error("rounds must be 2..10; requests must be 0..2000000") if not (2 <= args.rounds <= 10 and 0 <= args.requests <= 2000000) else None
    for name in (*PROFILES, "dnsbench"):
        require(getattr(args, name).is_file() and os.access(getattr(args, name), os.X_OK), "missing executable: " + name)
    return args


def main():
    args = arguments()
    if not args.inside_namespace:
        require(platform.system() == "Linux", "hosted lab requires Linux")
        args.output.mkdir(parents=True, exist_ok=False)
        namespace = "mosdns-lab-" + uuid.uuid4().hex
        env = dict(os.environ, MOSDNS_LAB_HOST_NS=os.readlink("/proc/self/ns/net"))
        command = ["bash", str(Path(__file__).with_name("deploy-lab.sh")), "--run", namespace,
                   sys.executable, str(Path(__file__).resolve()), *sys.argv[1:],
                   "--inside-namespace", "--namespace", namespace]
        with (args.output / "deployment.stdout").open("w") as stdout, (args.output / "deployment.stderr").open("w") as stderr:
            deployment = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=stderr,
                                          text=True, start_new_session=True)

            def terminate_deployment(signum, frame):
                # Signal the shell so its namespace/cgroup cleanup trap runs.
                deployment.send_signal(signal.SIGTERM)

            signal.signal(signal.SIGTERM, terminate_deployment)
            signal.signal(signal.SIGINT, terminate_deployment)
            for line in deployment.stdout:
                stdout.write(line)
                stdout.flush()
                print(line, end="", flush=True)
            code = deployment.wait()
        result_path = args.output / "results.json"
        if result_path.exists():
            value = json.loads(result_path.read_text())
        else:
            value = {"schema_version": 1, "suite": "hosted", "status": "failed", "source_commit": args.commit,
                     "checks": [], "measurements": [], "environment": {"namespace": namespace}, "limitations": [], "artifacts": []}
        listing = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
        gone = listing.returncode == 0 and namespace not in [line.split()[0] for line in listing.stdout.splitlines() if line.strip()]
        value["checks"].append({"name": "namespace-cleanup", "status": "passed" if gone else "failed",
                                "detail": {"namespace": namespace, "removed": gone, "deployment_exit_code": code}})
        if code != 0 or not gone:
            value["status"] = "failed"
        value["artifacts"] = [{"path": str(path.relative_to(args.output)), "sha256": sha256(path),
                                "size_bytes": path.stat().st_size}
                               for path in sorted(args.output.iterdir()) if path.is_file() and path.name != "results.json"]
        write_json(result_path, value)
        print(json.dumps({"status": value["status"], "result": str(result_path),
                          "measurements": len(value["measurements"])}), flush=True)
        return 0 if value["status"] == "passed" else 1
    require(args.namespace and re.fullmatch(r"mosdns-lab-[0-9a-f]{32}", args.namespace), "invalid owned namespace")
    lab = Lab(args)
    def interrupted(signum, frame):
        raise RuntimeError("suite interrupted by signal %d" % signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        lab.run()
    except Exception as exc:
        lab.result["checks"].append({"name": "suite-execution", "status": "failed", "detail": str(exc)})
        lab.result["status"] = "failed"
        print(str(exc), file=sys.stderr, flush=True)
    finally:
        lab.cleanup()
    return 0 if lab.result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
