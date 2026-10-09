#!/usr/bin/env python3
"""Opt-in isolated OpenWrt regression and bounded benchmark controller.

Default invocation performs read-only preflight. Only --run deploys ephemeral
resources. Artifacts are compiled by CI; this controller never invokes Go.
The JSON config lives outside the repository and is never copied to results.
No default resolver, production service, route, peer or interface is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone


class Blocked(RuntimeError):
    pass


class Failed(RuntimeError):
    pass


def require(value, message, exc=Failed):
    if not value:
        raise exc(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "expected regular input file", Blocked)
    return path.read_bytes()


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def safe_interface(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value),
            "invalid interface name", Blocked)
    return value


def integer(value, lower, upper, label):
    require(type(value) is int and lower <= value <= upper, "invalid " + label, Blocked)
    return value


def load_config(path):
    c = json.loads(regular(path))
    require(isinstance(c, dict), "config must be an object", Blocked)
    c.setdefault("host", "192.168.100.131")
    c.setdefault("ssh_user", "root")
    require(c["ssh_user"] == "root", "target requires root for scoped nft/cgroup operations", Blocked)
    require(ipaddress.ip_address(c["host"]).version == 4, "explicit IPv4 SSH host required", Blocked)
    for name in ("ssh_identity", "ssh_known_hosts", "cn_site_file", "cn_ip_file"):
        require(name in c and Path(c[name]).is_absolute(), "missing absolute " + name, Blocked)
        require(Path(c[name]).is_file() and not Path(c[name]).is_symlink(),
                "expected regular private input file", Blocked)
    require(re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", c.get("ssh_host_fingerprint", "")),
            "verified SSH host fingerprint required", Blocked)
    for name in ("direct_interface", "wireguard_interface"):
        safe_interface(c[name])
    require(c["direct_interface"] != c["wireguard_interface"], "direct/WG interfaces must differ", Blocked)
    require(ipaddress.ip_address(c["foreign_dns"]).version == 4, "numeric IPv4 foreign resolver required", Blocked)
    defaults = dict(ssh_port=22, resolver_file="/etc/resolv.conf", resolver_index=0,
                    remote_parent="/root", cgroup_parent="/sys/fs/cgroup/mosdns-tests",
                    listener_port=15473, mock_port=15474, proxy_port=15475, foreign_mock_port=15476,
                    minimum_available_kib=49152, minimum_runtime_available_kib=16384,
                    memory_max_bytes=33554432, helper_memory_max_bytes=25165824,
                    pids_max=64, gomemlimit="20MiB", gomaxprocs=2, set_timeout_seconds=10,
                    watchdog_seconds=900, query_timeout_seconds=5,
                    cn_domains=["www.baidu.com", "www.bilibili.com"],
                    foreign_domains=["example.com", "www.cloudflare.com"],
                    production_files=["/etc/config/network", "/etc/config/firewall", "/etc/config/dhcp"])
    for key, value in defaults.items():
        c.setdefault(key, value)
    for name in ("ssh_port", "listener_port", "mock_port", "proxy_port", "foreign_mock_port"):
        integer(c[name], 1024 if name != "ssh_port" else 1, 65535, name)
    require(len({c[n] for n in ("listener_port", "mock_port", "proxy_port", "foreign_mock_port")}) == 4,
            "owned ports must differ", Blocked)
    for name in ("direct_mark", "foreign_mark"):
        integer(c[name], 1, 4294967295, name)
    require(c["direct_mark"] != c["foreign_mark"], "DNS branch marks must differ", Blocked)
    for name in ("minimum_available_kib", "minimum_runtime_available_kib"):
        integer(c[name], 16384, 1048576, name)
    for name in ("memory_max_bytes", "helper_memory_max_bytes"):
        integer(c[name], 16777216, 134217728, name)
    integer(c["pids_max"], 8, 128, "pids_max")
    integer(c["gomaxprocs"], 1, 4, "gomaxprocs")
    integer(c["set_timeout_seconds"], 3, 180, "set_timeout_seconds")
    integer(c["watchdog_seconds"], 60, 3600, "watchdog_seconds")
    integer(c["query_timeout_seconds"], 1, 15, "query_timeout_seconds")
    integer(c["resolver_index"], 0, 8, "resolver_index")
    require(re.fullmatch(r"[1-9][0-9]{0,2}MiB", c["gomemlimit"]), "invalid gomemlimit", Blocked)
    require(int(c["gomemlimit"][:-3]) * 1048576 < c["memory_max_bytes"],
            "GOMEMLIMIT must leave cgroup headroom", Blocked)
    require(c["remote_parent"] == "/root", "remote staging parent must be /root flash", Blocked)
    require(re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", c["cgroup_parent"]),
            "existing delegated cgroup parent required", Blocked)
    for path in [c["resolver_file"], *c["production_files"]]:
        require(re.fullmatch(r"/[A-Za-z0-9_./-]+", path) and ".." not in Path(path).parts,
                "invalid target baseline path", Blocked)
    require(isinstance(c["production_files"], list) and 1 <= len(c["production_files"]) <= 20,
            "production file whitelist required", Blocked)
    for kind in ("cn_domains", "foreign_domains"):
        require(isinstance(c[kind], list) and 2 <= len(c[kind]) <= 8, "bounded domain list required", Blocked)
        for name in c[kind]:
            require(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", name)
                    and all(0 < len(label) <= 63 for label in name.split(".")), "invalid domain", Blocked)
    require(not set(c["cn_domains"]) & set(c["foreign_domains"]), "branch domains overlap", Blocked)
    b = c.setdefault("benchmark", {})
    for key, value in dict(enabled=True, queries=2000, concurrency=[1, 4], rounds=2, minimum_seconds=2).items():
        b.setdefault(key, value)
    require(type(b["enabled"]) is bool, "benchmark enabled must be boolean", Blocked)
    integer(b["queries"], 100, 100000, "benchmark queries")
    integer(b["rounds"], 1, 3, "benchmark rounds")
    require(b["concurrency"] and len(set(b["concurrency"])) == len(b["concurrency"]),
            "unique benchmark concurrency required", Blocked)
    for concurrency in b["concurrency"]:
        integer(concurrency, 1, 16, "benchmark concurrency")
    require(type(b["minimum_seconds"]) in (float, int) and 1 <= b["minimum_seconds"] <= 30,
            "benchmark minimum duration invalid", Blocked)
    return c


def static_arm64(data):
    require(data[:6] == b"\x7fELF\x02\x01" and len(data) >= 64, "artifact must be ELF64 LE", Blocked)
    require(struct.unpack_from("<H", data, 18)[0] == 183, "artifact must target ARM64", Blocked)
    phoff, = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    require(size >= 56 and phoff + size * count <= len(data), "invalid ELF program table", Blocked)
    for index in range(count):
        offset = phoff + index * size
        typ, = struct.unpack_from("<I", data, offset)
        require(typ != 3, "ELF requests a dynamic interpreter", Blocked)
        if typ == 2:
            start, = struct.unpack_from("<Q", data, offset + 8)
            length, = struct.unpack_from("<Q", data, offset + 32)
            require(start + length <= len(data), "invalid dynamic section", Blocked)
            for entry in range(start, start + length - 15, 16):
                tag, = struct.unpack_from("<q", data, entry)
                require(tag != 1, "ELF has DT_NEEDED dependencies", Blocked)
                if tag == 0:
                    break


def load_bundle(directory, commit):
    directory = Path(directory)
    manifest = json.loads(regular(directory / "bundle.json"))
    require(manifest.get("schema_version") == 1 and manifest.get("source_commit") == commit
            and manifest.get("goarch") == "arm64", "bundle source/architecture mismatch", Blocked)
    files = manifest.get("files", {})
    require({"mosdns-full", "mosdns-minimal", "mosdns-baseline", "dnsbench", "routerproxy"} <= files.keys(),
            "bundle missing target binaries", Blocked)
    binaries = {}
    for name in ("mosdns-full", "mosdns-minimal", "mosdns-baseline", "dnsbench", "routerproxy"):
        metadata = files[name]
        data = regular(directory / name)
        require(metadata.get("sha256") == digest(data) and metadata.get("bytes") == len(data),
                "bundle binary hash/size mismatch: " + name, Blocked)
        expected = manifest.get("baseline_commit") if name == "mosdns-baseline" else commit
        require(metadata.get("source_commit") == expected and re.fullmatch(r"[a-f0-9]{40}", expected or ""),
                "bundle binary source mismatch: " + name, Blocked)
        static_arm64(data)
        binaries[name] = data
    return manifest, binaries


def decode_name(packet, offset, visited=None):
    visited = set() if visited is None else visited
    labels, ended = [], None
    while True:
        require(offset < len(packet), "truncated DNS name")
        length = packet[offset]
        if length & 192 == 192:
            require(offset + 1 < len(packet), "truncated DNS pointer")
            pointer = ((length & 63) << 8) | packet[offset + 1]
            require(pointer not in visited and len(visited) < 128, "cyclic DNS pointer")
            visited.add(pointer)
            suffix, _ = decode_name(packet, pointer, visited)
            labels.append(suffix)
            ended = offset + 2
            break
        require(length < 64, "invalid DNS label")
        offset += 1
        if length == 0:
            ended = offset
            break
        require(offset + length <= len(packet), "truncated DNS label")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    return ".".join(labels).rstrip("."), ended


def parse_answer(packet, query_id, name, typ, require_addresses=True):
    require(len(packet) >= 12, "short DNS response")
    received, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    require(received == query_id and flags & 0x8000 and not flags & 0x0200,
            "DNS ID/QR/truncation assertion failed")
    require(flags & 15 == 0 and qd == 1, "DNS rcode/question count assertion failed")
    question, offset = decode_name(packet, 12)
    require(offset + 4 <= len(packet), "truncated DNS question")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    require(question == name.lower().rstrip(".") and qtype == typ and qclass == 1,
            "DNS question assertion failed")
    offset += 4
    addresses = []
    for index in range(an + ns + ar):
        _, offset = decode_name(packet, offset)
        require(offset + 10 <= len(packet), "truncated DNS RR")
        rtype, rclass, ttl, length = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        require(offset + length <= len(packet), "truncated DNS RDATA")
        if index < an and rtype in (1, 28):
            require(rclass == 1 and length == {1: 4, 28: 16}[rtype], "invalid address RR")
            addresses.append({"ip": str(ipaddress.ip_address(packet[offset:offset + length])),
                              "type": {1: "A", 28: "AAAA"}[rtype], "ttl": ttl})
        offset += length
    require(offset == len(packet), "trailing DNS response bytes")
    if require_addresses:
        require(any(row["type"] == {1: "A", 28: "AAAA"}[typ] for row in addresses),
                "NODATA does not cover requested address family")
    return {"name": name, "type": {1: "A", 28: "AAAA"}[typ], "rcode": 0,
            "addresses": addresses, "id_ok": True, "question_ok": True, "truncated": False}


def exchange(host, port, protocol, name, typ, timeout, require_addresses=True):
    query_id = secrets.randbelow(65536)
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    query = struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", typ, 1)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect((host, port))
        if protocol == "udp":
            stream.send(query)
            packet = stream.recv(65535)
        else:
            stream.sendall(struct.pack("!H", len(query)) + query)
            def receive(count):
                data = b""
                while len(data) < count:
                    part = stream.recv(count - len(data))
                    require(part, "DNS TCP closed before complete response")
                    data += part
                return data
            length, = struct.unpack("!H", receive(2))
            packet = receive(length)
    elapsed_ms = (time.monotonic() - started) * 1000
    answer = parse_answer(packet, query_id, name, typ, require_addresses)
    answer["elapsed_ms"] = elapsed_ms
    answer["wire_sha256"] = digest(packet)
    return answer


def nft_view(value):
    """Exact production rule structure, excluding counters/handles/live elements.

    Dynamic elements and their expiration are separately declared unverified;
    stripping them never masks a change to a set definition or expression.
    """
    if isinstance(value, list):
        return [nft_view(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in ("handle", "metainfo"):
                continue
            if key == "elem" and "type" in value and "table" in value and "timeout" in value.get("flags", []):
                continue
            if key == "counter" and isinstance(item, dict):
                item = {k: v for k, v in item.items() if k not in ("packets", "bytes")}
            if key in ("packets", "bytes") and "name" in value and "family" in value:
                continue
            result[key] = nft_view(item)
        return result
    return value


def table_state(value, table):
    counts, learned = {}, {4: set(), 6: set()}
    for item in value["nftables"]:
        if "counter" in item:
            counter = item["counter"]
            require(counter.get("table") == table, "counter outside owned table")
            counts[counter["name"]] = counter["packets"]
        if "set" in item:
            record = item["set"]
            require(record.get("table") == table, "set outside owned table")
            family = {"cn_site4": 4, "cn_site6": 6}.get(record["name"])
            if family:
                for element in record.get("elem", []):
                    if isinstance(element, dict):
                        element = element.get("elem", element)
                        element = element.get("val", element)
                    learned[family].add(str(ipaddress.ip_address(element)))
    require({"direct", "foreign", "wrong", "website_direct", "website_foreign", "website_wrong"} <= counts.keys(), "missing DNS path counters")
    return counts, learned


class Controller:
    def __init__(self, config, bundle, binaries, output, commit, pages_script=None):
        self.c, self.bundle, self.binaries = config, bundle, binaries
        self.out, self.commit, self.pages_script = Path(output), commit, pages_script
        self.owner = secrets.token_hex(16)
        self.table = "mw_" + self.owner[:12]
        self.root = "/root/mosdns-workflow-" + self.owner
        self.cg = config["cgroup_parent"] + "/mw_" + self.owner
        self.lock = "/root/.mosdns-workflow.lock"
        self.deployed = False
        self.program_logs = []
        self.pages_root = self.out.parent / "pages131" if pages_script else None
        self.page_result = dict(schema_version=1, suite="pages131", status="failed", source_commit=commit,
                                checks=[], measurements=[], environment={}, limitations=[
                                    "Browser rendering runs on runner; origin DNS and IPv4 TCP on router.",
                                    "Learned-only non-CN-site route classification and public IPv6 page egress remain untested.",
                                    "Public page content/CDN failures vary; DNS replay covers successful DNS responses separately."
                                ], artifacts=[]) if pages_script else None
        self.baseline = None
        self.boot = None
        self.direct_dns = None
        self.result = dict(schema_version=1, suite="router131", status="blocked", source_commit=commit,
                           checks=[], measurements=[], environment={}, limitations=[
                               "Private configuration and production configuration contents are not archived.",
                               "No production resolver, route, WireGuard peer or interface is changed.",
                               "CN-IP input is parsed and hashed; learned-only website route and public IPv6 egress are not tested.",
                               "Dynamic production nft set elements are excluded from cleanup structure comparison.",
                               "NFT timing bounds include DNS exchange, SSH and userspace snapshot overhead; they are not syscall timings.",
                               "Short fixed-count trials are retained but excluded from throughput conclusions.",
                               "Two or three alternating rounds describe this run, not long-term or statistical significance."
                           ], artifacts=[])
        self.ssh = ["ssh", "-T", "-F", "/dev/null", "-p", str(config["ssh_port"]),
                    "-i", config["ssh_identity"], "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                    "-o", "UserKnownHostsFile=" + config["ssh_known_hosts"],
                    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
                    "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                    "-o", "ControlMaster=no", "-o", "ControlPath=none", "root@" + config["host"]]

    def check(self, name, status, detail):
        self.result["checks"].append(dict(name=name, status=status, detail=detail))

    def raw(self, name, data):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name), "invalid evidence name")
        path = self.out / name
        with path.open("xb") as stream:
            stream.write(data)
        self.result["artifacts"].append(dict(path=name, sha256=digest(data), bytes=len(data)))
        return path

    def remote(self, script, timeout=20):
        process = subprocess.run(self.ssh + ["sh -s"], input=script.encode(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        # Remote diagnostics can contain private configuration. Never echo them.
        require(process.returncode == 0, "SSH target command failed (exit %d)" % process.returncode)
        return process.stdout

    def guard(self):
        return ("set -eu\numask 077\nR=" + shlex.quote(self.root) + "\nCG=" + shlex.quote(self.cg)
                + "\nTABLE=" + self.table + "\nTOKEN=" + self.owner + "\n"
                + "[ \"$(cat /proc/sys/kernel/random/boot_id)\" = " + shlex.quote(self.boot) + " ]\n"
                + "[ -d \"$R\" ] && [ ! -L \"$R\" ] && [ \"$(cat \"$R/.owner\")\" = \"$TOKEN\" ]\n")

    def read_state(self):
        token = "FRAME_" + self.owner
        commands = {
            "boot": "cat /proc/sys/kernel/random/boot_id",
            "arch": "uname -m", "uptime": "cat /proc/uptime", "memory": "cat /proc/meminfo",
            "resolver": "cat " + shlex.quote(self.c["resolver_file"]),
            "configs": "sha256sum " + " ".join(map(shlex.quote, self.c["production_files"])),
            "rules": "ip -4 rule show; ip -6 rule show",
            "routes": "ip -4 route show table all; ip -6 route show table all",
            "addresses": "ip -o addr show", "nft": "nft -j list ruleset", "kernel": "dmesg",
            "wg": "wg show interfaces", "wg_allowed": "wg show " + self.c["wireguard_interface"] + " allowed-ips",
            "wg_endpoint": "wg show " + self.c["wireguard_interface"] + " endpoints",
        }
        script = "set -eu\n" + "\n".join("printf '%s\\n' " + shlex.quote(token + key) + "\n" + cmd
                                            for key, cmd in commands.items())
        data = self.remote(script, 30).decode("utf-8")
        fields = {}
        for key in commands:
            marker = token + key + "\n"
            require(marker in data, "incomplete target snapshot")
            fragment = data.split(marker, 1)[1].split(token, 1)[0]
            fields[key] = fragment
        return fields

    def summarize_state(self, state):
        stable_fields = dict(state)
        stable_fields["addresses"] = re.sub(r"(valid_lft|preferred_lft) [0-9]+sec", r"\1 <LIVE_TIMER>", state["addresses"])
        stable_fields["routes"] = re.sub(r"\bexpires [0-9]+(?:sec|s)?", "expires <LIVE_TIMER>", state["routes"])
        stable = {key: digest(stable_fields[key].encode()) for key in
                  ("configs", "resolver", "rules", "routes", "addresses", "wg", "wg_allowed", "wg_endpoint")}
        stable["nft_structure"] = digest(json.dumps(nft_view(json.loads(state["nft"])), sort_keys=True).encode())
        available = re.search(r"^MemAvailable:\s+(\d+)", state["memory"], re.M)
        require(available, "MemAvailable missing", Blocked)
        return dict(boot_id=state["boot"].strip(), architecture=state["arch"].strip(),
                    memory_available_kib=int(available[1]), stable_sha256=stable,
                    kernel_sha256=digest(state["kernel"].encode()))

    def preflight(self):
        host_key_name = self.c["host"] if self.c["ssh_port"] == 22 else "[" + self.c["host"] + "]:" + str(self.c["ssh_port"])
        found = subprocess.run(["ssh-keygen", "-F", host_key_name, "-f", self.c["ssh_known_hosts"]],
                               capture_output=True, text=True)
        require(found.returncode == 0, "target host missing from pinned known_hosts", Blocked)
        checked = subprocess.run(["ssh-keygen", "-lf", "-", "-E", "sha256"],
                                 input=found.stdout, capture_output=True, text=True)
        require(checked.returncode == 0 and any(self.c["ssh_host_fingerprint"] == line.split()[1]
                for line in checked.stdout.splitlines() if len(line.split()) >= 2),
                "target host fingerprint does not match pinned known_hosts", Blocked)
        state = self.read_state()
        summary = self.summarize_state(state)
        self.boot = summary["boot_id"]
        require(re.fullmatch(r"[a-f0-9-]{36}", self.boot), "invalid target boot ID", Blocked)
        require(summary["architecture"] == "aarch64", "target architecture is not aarch64", Blocked)
        require(summary["memory_available_kib"] >= self.c["minimum_available_kib"],
                "insufficient target memory for configured limits", Blocked)
        require(self.c["wireguard_interface"] in state["wg"].split(), "configured existing WireGuard interface missing", Blocked)
        resolvers = re.findall(r"^nameserver\s+([^\s#]+)", state["resolver"], re.M)
        require(len(resolvers) > self.c["resolver_index"], "configured default resolver index missing", Blocked)
        self.direct_dns = str(ipaddress.IPv4Address(resolvers[self.c["resolver_index"]]))
        require(self.direct_dns != self.c["foreign_dns"], "direct and tunnel upstreams must differ", Blocked)
        cg = self.c["cgroup_parent"]
        # nft --check validates the installed cgroup socket expression without installing a rule.
        relative = cg.removeprefix("/sys/fs/cgroup/")
        level = len(relative.split("/"))
        nft_check = f'table inet {self.table} {{ chain test {{ type filter hook output priority 10; socket cgroupv2 level {level} "{relative}" counter; }} }}'
        ports = "|".join(f"{self.c[key]:04X}" for key in ("listener_port", "mock_port", "proxy_port", "foreign_mock_port"))
        script = f'''set -eu
[ "$(id -u)" = 0 ]
for tool in nft ip wg sha256sum tar awk stat; do command -v "$tool" >/dev/null; done
[ "$(readlink -f /root)" = /root ]
case "$(stat -f -c %T /root)" in tmpfs|ramfs) exit 40;; esac
[ ! -e {shlex.quote(self.lock)} ]
[ -d {shlex.quote(cg)} ] && [ ! -L {shlex.quote(cg)} ]
grep -qw memory {shlex.quote(cg + '/cgroup.subtree_control')}
grep -qw pids {shlex.quote(cg + '/cgroup.subtree_control')}
! awk '$2 ~ /:({ports})$/ {{found=1}} END{{exit !found}}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6
ip link show dev {self.c['direct_interface']} >/dev/null
ip link show dev {self.c['wireguard_interface']} >/dev/null
ip -4 route get {self.direct_dns} mark {self.c['direct_mark']} oif {self.c['direct_interface']}
ip -4 route get {self.c['foreign_dns']} mark {self.c['foreign_mark']} oif {self.c['wireguard_interface']}
nft -c -f - <<'NFTCHECK'
{nft_check}
NFTCHECK
'''
        try:
            routes = self.remote(script, 25).decode()
        except Failed as error:
            raise Blocked("target prerequisites missing: ports/lock/flash/delegated cgroup/WG routes/nft cgroup matcher") from error
        require(re.search(r"\bdev " + re.escape(self.c["direct_interface"]) + r"\b", routes)
                and re.search(r"\bdev " + re.escape(self.c["wireguard_interface"]) + r"\b", routes),
                "upstream route interface mismatch", Blocked)
        cn_site, cn_ip = regular(self.c["cn_site_file"]), regular(self.c["cn_ip_file"])
        prefixes = []
        for line in cn_ip.decode().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                prefixes.append(ipaddress.ip_network(line, strict=False))
        require(cn_site.strip() and prefixes, "CN-site/CN-IP inputs empty", Blocked)
        self.baseline = state
        self.result["environment"] = dict(summary, owner=self.owner, direct_dns=self.direct_dns,
                                              foreign_dns=self.c["foreign_dns"], direct_interface=self.c["direct_interface"],
                                              wireguard_interface=self.c["wireguard_interface"],
                                              cn_site_sha256=digest(cn_site), cn_site_lines=len(cn_site.splitlines()),
                                              cn_ip_sha256=digest(cn_ip), cn_ip_prefixes=len(prefixes),
                                              bundle_sha256=digest(json.dumps(self.bundle, sort_keys=True).encode()),
                                              configured_limits={key: self.c[key] for key in
                                                  ("memory_max_bytes", "helper_memory_max_bytes", "pids_max", "gomaxprocs", "gomemlimit")})
        self.raw("preflight.json", (json.dumps(self.result["environment"], indent=2) + "\n").encode())
        self.check("preflight", "passed", "Pinned SSH, ARM64, default resolver, existing WG routes, owned ports and delegated cgroup/nft matcher verified")

    def yaml(self, benchmark=False, cache=True):
        c, root = self.c, self.root
        if benchmark:
            direct = f"127.0.0.1:{c['mock_port']}"
            foreign = f"127.0.0.1:{c['foreign_mock_port']}"
            direct_opts = foreign_opts = ""
            final = "      - exec: accept\n"
        else:
            direct, foreign = self.direct_dns + ":53", c["foreign_dns"] + ":53"
            direct_opts = f"      so_mark: {c['direct_mark']}\n      bind_to_device: {json.dumps(c['direct_interface'])}\n"
            foreign_opts = f"      so_mark: {c['foreign_mark']}\n      bind_to_device: {json.dumps(c['wireguard_interface'])}\n"
            final = (f'      - matches: ["qname $cn_site"]\n        exec: nftset inet,{self.table},cn_site4,ipv4_addr,32 '
                     f'inet,{self.table},cn_site6,ipv6_addr,128\n      - exec: accept\n')
        cache_block = ("  - tag: cache\n    type: cache\n    args:\n      size: 1024\n      lazy_cache_ttl: 0\n") if cache else ""
        cache_exec = '      - exec: $cache\n      - matches: ["has_resp"]\n        exec: goto finalize\n' if cache else ""
        return (f'log:\n  level: warn\nplugins:\n  - tag: cn_site\n    type: domain_set\n    args:\n      files: [{json.dumps(root + "/cn-site.txt")}]\n'
                + cache_block + "  - tag: direct\n    type: forward\n    args:\n" + direct_opts
                + f'      upstreams: [{{addr: "{direct}"}}]\n'
                + "  - tag: foreign\n    type: forward\n    args:\n" + foreign_opts
                + f'      upstreams: [{{addr: "{foreign}"}}]\n'
                + "  - tag: finalize\n    type: sequence\n    args:\n" + final
                + '  - tag: resolve_cn\n    type: sequence\n    args:\n      - exec: $direct\n      - exec: goto finalize\n'
                + "  - tag: main\n    type: sequence\n    args:\n" + cache_exec
                + '      - matches: ["qname $cn_site"]\n        exec: goto resolve_cn\n      - exec: $foreign\n      - exec: goto finalize\n'
                + f'  - type: udp_server\n    args:\n      listen: "{c["host"]}:{c["listener_port"]}"\n      entry: main\n'
                + f'  - type: tcp_server\n    args:\n      listen: "{c["host"]}:{c["listener_port"]}"\n      entry: main\n'
                + f'  - type: udp_server\n    args:\n      listen: "127.0.0.1:{c["listener_port"]}"\n      entry: main\n'
                + f'  - type: tcp_server\n    args:\n      listen: "127.0.0.1:{c["listener_port"]}"\n      entry: main\n')

    def deploy(self):
        import io
        import tarfile
        c = self.c
        group_path = self.cg.removeprefix("/sys/fs/cgroup/") + "/app"
        level = len(group_path.split("/"))
        match = f'socket cgroupv2 level {level} "{group_path}"'
        helpers_match = f'socket cgroupv2 level {level} "{group_path.rsplit("/", 1)[0]}/helpers"' 
        nft = f'''table inet {self.table} {{
 comment "mosdns-workflow-{self.owner}"
 counter direct {{ }}
 counter foreign {{ }}
 counter wrong {{ }}
 counter website_direct {{ }}
 counter website_foreign {{ }}
 counter website_wrong {{ }}
 set cn_site4 {{ type ipv4_addr; flags timeout; timeout {c['set_timeout_seconds']}s; }}
 set cn_site6 {{ type ipv6_addr; flags timeout; timeout {c['set_timeout_seconds']}s; }}
 chain output {{ type filter hook output priority 10; policy accept;
  {match} meta mark {c['direct_mark']} ip daddr {self.direct_dns} meta l4proto {{ udp, tcp }} th dport 53 oifname "{c['direct_interface']}" counter name direct return
  {match} meta mark {c['foreign_mark']} ip daddr {c['foreign_dns']} meta l4proto {{ udp, tcp }} th dport 53 oifname "{c['wireguard_interface']}" counter name foreign return
  {match} meta mark {{ {c['direct_mark']}, {c['foreign_mark']} }} counter name wrong drop
  {helpers_match} meta mark {c['direct_mark']} tcp dport {{ 80, 443 }} oifname "{c['direct_interface']}" counter name website_direct return
  {helpers_match} meta mark {c['foreign_mark']} tcp dport {{ 80, 443 }} oifname "{c['wireguard_interface']}" counter name website_foreign return
  {helpers_match} meta mark {{ {c['direct_mark']}, {c['foreign_mark']} }} counter name website_wrong drop
 }}
}}
'''
        payload = dict(self.binaries)
        payload.update({"cn-site.txt": regular(c["cn_site_file"]), "cn-ip.txt": regular(c["cn_ip_file"]), "real.yaml": self.yaml().encode(),
                        "bench.yaml": self.yaml(benchmark=True).encode(), "owned.nft": nft.encode(),
                        "queries.txt": b"cn-site.test A\ncn-site.test AAAA\nforeign.test A\nforeign.test AAAA\nnxdomain.test A\n"})
        # CN benchmark fixture appended to a frozen copy; real CN list is untouched.
        payload["bench-site.txt"] = payload["cn-site.txt"] + b"\ndomain:cn-site.test\n"
        payload["bench.yaml"] = payload["bench.yaml"].replace(b"/cn-site.txt", b"/bench-site.txt")
        payload["cleanup.sh"] = self.cleanup_script().encode()
        checksums = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(payload.items()))
        payload["payload.sha256"] = checksums.encode()
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for name, content in payload.items():
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(content), (0o700 if name in self.binaries or name.endswith(".sh") else 0o600)
                archive.addfile(info, io.BytesIO(content))
        required_free_kib = (len(data.getvalue()) + 1023) // 1024 + 32768
        def flash_capacity():
            free = self.remote("set -eu\ndf -Pk /root | awk 'NR==2 {print $4}'\n").decode().strip()
            require(free.isdigit() and int(free) >= required_free_kib,
                    "insufficient /root flash for payload plus 32 MiB log/recovery reserve", Blocked)
        flash_capacity()
        self.result["environment"]["deployment_required_free_kib"] = required_free_kib
        # Owned lock and directory created with mkdir, never adopting an old directory.
        self.deployed = True  # Mutation may succeed even when SSH times out before acknowledgement.
        self.remote(f'''set -eu
umask 077
[ "$(cat /proc/sys/kernel/random/boot_id)" = {shlex.quote(self.boot)} ]
mkdir {shlex.quote(self.lock)}
trap 'if [ -f {shlex.quote(self.lock + '/owner')} ] && [ "$(cat {shlex.quote(self.lock + '/owner')})" = {self.owner} ]; then rm {shlex.quote(self.lock + '/owner')}; rmdir {shlex.quote(self.lock)}; elif [ ! -e {shlex.quote(self.lock + '/owner')} ]; then rmdir {shlex.quote(self.lock)} 2>/dev/null || :; fi' EXIT
printf '%s\\n' {self.owner} > {shlex.quote(self.lock + '/owner')}
mkdir {shlex.quote(self.root)}
printf '%s\\n' {self.owner} > {shlex.quote(self.root + '/.owner')}
trap - EXIT
''')
        self.deployed = True
        flash_capacity()  # Recheck immediately before the only large flash transfer.
        process = subprocess.run(self.ssh + ["tar -xf - -C " + shlex.quote(self.root)], input=data.getvalue(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        require(process.returncode == 0, "payload upload failed")
        script = self.guard() + f'''
cd "$R"
sha256sum -c payload.sha256 >/dev/null
nohup sh -c 'child=""; trap '"'"'test -z "$child" || kill "$child" 2>/dev/null || :; exit 0'"'"' TERM INT HUP; sleep "$1" & child=$!; wait "$child"; exec sh "$2/cleanup.sh"' sh {c['watchdog_seconds']} "$R" > "$R/watchdog.log" 2>&1 < /dev/null &
printf '%s\\n' "$!" > "$R/watchdog.pid"
awk '{{print $22}}' "/proc/$(cat "$R/watchdog.pid")/stat" > "$R/watchdog.start"
mkdir "$CG"
printf '+memory +pids\\n' > "$CG/cgroup.subtree_control"
mkdir "$CG/app" "$CG/helpers"
for g in app helpers; do
  if [ "$g" = app ]; then limit={c['memory_max_bytes']}; else limit={c['helper_memory_max_bytes']}; fi
  printf '%s\\n' "$limit" > "$CG/$g/memory.max"
  printf '0\\n' > "$CG/$g/memory.swap.max"
  printf '1\\n' > "$CG/$g/memory.oom.group"
  printf '%s\\n' {c['pids_max']} > "$CG/$g/pids.max"
  [ -f "$CG/$g/cgroup.kill" ]
done
nft -c -f "$R/owned.nft"
nft -f "$R/owned.nft"
'''
        self.remote(script, 30)
        self.check("deployment", "passed", "CI static binaries verified; owned flash directory, lock, limited cgroups and isolated nft table created")

    def cleanup_script(self):
        return f'''#!/bin/sh
set -eu
R={shlex.quote(self.root)}
CG={shlex.quote(self.cg)}
TOKEN={self.owner}
LOCK={shlex.quote(self.lock)}
[ "$(cat /proc/sys/kernel/random/boot_id)" = {shlex.quote(self.boot)} ]
lock_owned() {{ [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && [ -f "$LOCK/owner" ] && [ "$(cat "$LOCK/owner")" = "$TOKEN" ]; }}
root_owned() {{ [ -d "$R" ] && [ ! -L "$R" ] && [ -f "$R/.owner" ] && [ "$(cat "$R/.owner")" = "$TOKEN" ]; }}
if ! root_owned; then
 # Only the unique empty directory can be removed when an owned lock proves
 # our mkdir transaction was interrupted before writing its root marker.
 lock_owned || exit 1
 [ ! -e "$R" ] || rmdir "$R"
 rm "$LOCK/owner"
 rmdir "$LOCK"
 exit 0
fi
for g in app helpers; do
 if [ -d "$CG/$g" ]; then
  [ ! -L "$CG/$g" ]
  if [ -n "$(cat "$CG/$g/cgroup.procs")" ]; then
   while read -r pid; do kill -TERM "$pid" 2>/dev/null || :; done < "$CG/$g/cgroup.procs"
   sleep 1
   [ -z "$(cat "$CG/$g/cgroup.procs")" ] || printf '1\\n' > "$CG/$g/cgroup.kill"
  fi
  rmdir "$CG/$g"
 fi
done
[ ! -d "$CG" ] || rmdir "$CG"
if nft list table inet {self.table} >/dev/null 2>&1; then
 nft list table inet {self.table} | grep -F 'mosdns-workflow-{self.owner}' >/dev/null
 nft delete table inet {self.table}
fi
# Idempotent when the watchdog already released this run's lock.
if [ -e "$LOCK" ]; then
 lock_owned
 rm "$LOCK/owner"
 rmdir "$LOCK"
fi
'''

    def healthy(self):
        response = self.remote(self.guard() + f'''[ "$(awk '/^MemAvailable:/ {{print $2}}' /proc/meminfo)" -ge {self.c['minimum_runtime_available_kib']} ]
for g in app helpers; do
 awk '$2 != 0 {{bad=1}} END {{exit bad}}' "$CG/$g/memory.events" "$CG/$g/pids.events"
done
''')
        return response

    def start_app(self, profile, config):
        c = self.c
        log_name = f"{profile}-{config}-launch-{len(self.program_logs):03d}.log"
        self.program_logs.append(log_name)
        script = self.guard() + f'''
[ -z "$(cat "$CG/app/cgroup.procs")" ]
[ "$(awk '/^MemAvailable:/ {{print $2}}' /proc/meminfo)" -ge {c['minimum_available_kib']} ]
sh -c 'printf "%s\\n" "$$" > "$1/cgroup.procs"; shift; ulimit -f 256; exec env GOMEMLIMIT={c['gomemlimit']} GOMAXPROCS={c['gomaxprocs']} "$@"' sh "$CG/app" "$R/mosdns-{profile}" start -c "$R/{config}" --cpu {c['gomaxprocs']} > "$R/{log_name}" 2>&1 < /dev/null &
printf '%s\\n' "$!" > "$R/app.pid"
'''
        self.remote(script)
        deadline = time.monotonic() + 10
        port_hex = f"{c['listener_port']:04X}"
        while True:
            try:
                self.remote(self.guard() + f'''[ -n "$(cat "$CG/app/cgroup.procs")" ]
awk '$2 ~ /:{port_hex}$/ {{found=1}} END{{exit !found}}' /proc/net/tcp
awk '$2 ~ /:{port_hex}$/ {{found=1}} END{{exit !found}}' /proc/net/udp
''')
                break
            except Failed:
                require(time.monotonic() < deadline, "application readiness timed out")
                time.sleep(0.2)
        self.healthy()

    def stop_app(self, label):
        self.healthy()
        snapshot = self.remote(self.guard() + '''for g in app helpers; do
 for field in memory.peak memory.events pids.events cpu.stat; do
  printf '==%s/%s==\\n' "$g" "$field"
  cat "$CG/$g/$field"
 done
done
for pid in $(cat "$CG/app/cgroup.procs"); do
 grep -E '^(Name|VmRSS|VmHWM|Threads):' "/proc/$pid/status"
done
''')
        self.raw(label + "-resources.txt", snapshot)
        self.remote(self.guard() + '''while read -r pid; do kill -TERM "$pid"; done < "$CG/app/cgroup.procs"
i=0
while [ -n "$(cat "$CG/app/cgroup.procs")" ] && [ "$i" -lt 20 ]; do sleep 0.1; i=$((i+1)); done
[ -z "$(cat "$CG/app/cgroup.procs")" ]
''')

    def snapshot_table(self, label):
        data = self.remote(self.guard() + 'nft -j list table inet "$TABLE"\n')
        self.raw(label + ".json", data)
        counts, learned = table_state(json.loads(data), self.table)
        require(counts["wrong"] == 0 and counts["website_wrong"] == 0, "wrong owned DNS/website destination/interface guard fired")
        return counts, learned

    def flush(self):
        self.remote(self.guard() + 'nft flush set inet "$TABLE" cn_site4\nnft flush set inet "$TABLE" cn_site6\n')

    def real_queries(self, profile):
        self.flush()
        self.start_app(profile, "real.yaml")
        cached = {}
        for branch, domains in (("direct", self.c["cn_domains"]), ("foreign", self.c["foreign_domains"])):
            # A new name per transport ensures each cold transport exercises an upstream.
            for index, name in enumerate(domains):
                protocol = ("udp", "tcp")[index % 2]
                for typ in (1, 28):
                    label = f"{profile}-cold-{branch}-{index}-{typ}"
                    before, _ = self.snapshot_table(label + "-before")
                    began = time.monotonic()
                    answer = exchange(self.c["host"], self.c["listener_port"], protocol, name, typ,
                                      self.c["query_timeout_seconds"])
                    after, learned = self.snapshot_table(label + "-after")
                    require(after[branch] > before[branch], "cold query did not reach expected upstream branch")
                    other = "foreign" if branch == "direct" else "direct"
                    require(after[other] == before[other], "query reached wrong upstream branch")
                    addresses = {row["ip"] for row in answer["addresses"] if row["type"] == {1: "A", 28: "AAAA"}[typ]}
                    if branch == "direct":
                        require(addresses <= learned[{1: 4, 28: 6}[typ]], "CN answer missing from learned nft set")
                        cached[(name, typ)] = (answer, began, protocol)
                    self.raw(label + "-answer.json", (json.dumps(answer, indent=2) + "\n").encode())
                    self.result["measurements"].append(dict(kind="real_dns", profile=profile, phase="cold", branch=branch,
                                                           protocol=protocol, **answer,
                                                           add_visible_upper_ms=(time.monotonic()-began)*1000))
                    self.healthy()
        self.flush()
        _, empty = self.snapshot_table(profile + "-cache-empty")
        require(empty == {4: set(), 6: set()}, "owned learned sets did not flush")
        for index, ((name, typ), (cold, began, protocol)) in enumerate(cached.items()):
            label = f"{profile}-cache-{index}"
            before, _ = self.snapshot_table(label + "-before")
            replay_start = time.monotonic()
            answer = exchange(self.c["host"], self.c["listener_port"], protocol, name, typ,
                              self.c["query_timeout_seconds"])
            after, learned = self.snapshot_table(label + "-after")
            require(after == before, "cache replay produced an upstream DNS packet")
            old_ips = {row["ip"] for row in cold["addresses"]}
            require({row["ip"] for row in answer["addresses"]} == old_ips, "cached answer addresses changed")
            for row in answer["addresses"]:
                original = next(old for old in cold["addresses"] if old["ip"] == row["ip"])
                require(0 < row["ttl"] <= original["ttl"] and time.monotonic()-began <= original["ttl"],
                        "cache replay outside original TTL")
                require(row["ip"] in learned[ipaddress.ip_address(row["ip"]).version], "cached answer did not rebuild nft set")
            self.raw(label + "-answer.json", (json.dumps(answer, indent=2) + "\n").encode())
            self.result["measurements"].append(dict(kind="real_dns", profile=profile, phase="cache_rebuild", branch="direct",
                                                   protocol=protocol, **answer,
                                                   rebuild_visible_upper_ms=(time.monotonic()-replay_start)*1000))
        self.check(profile + "-real-dns", "passed", "Cold A/AAAA upstream branch/interface counters and cache replay/rebuild assertions passed")
        # Delete one actual A/AAAA member; cache replay re-adds it without an upstream packet.
        name, typ = next(iter(cached))
        cold, _, protocol = cached[(name, typ)]
        address = cold["addresses"][0]["ip"]
        version = ipaddress.ip_address(address).version
        deleted_start = time.monotonic()
        self.remote(self.guard() + f'nft delete element inet "$TABLE" cn_site{version} {{ {address} }}\n')
        before, learned = self.snapshot_table(profile + "-deleted")
        require(address not in learned[version], "manual element delete did not become visible")
        self.result["measurements"].append(dict(kind="nft_delete", profile=profile,
                                               visible_upper_ms=(time.monotonic()-deleted_start)*1000))
        answer = exchange(self.c["host"], self.c["listener_port"], protocol, name, typ, self.c["query_timeout_seconds"])
        after, learned = self.snapshot_table(profile + "-delete-rebuilt")
        require(after == before and address in learned[version], "manual-delete cache rebuild failed")
        # Start all timers together. Query each cached response only once, then watch natural expiry.
        self.flush()
        expiry_start = time.monotonic()
        answer = exchange(self.c["host"], self.c["listener_port"], protocol, name, typ, self.c["query_timeout_seconds"])
        _, learned = self.snapshot_table(profile + "-expiry-added")
        expected = {row["ip"] for row in answer["addresses"]}
        require(expected <= learned[version], "expiry test element missing at start")
        last_present = time.monotonic()
        previous_observation = last_present
        largest_poll_gap = 0
        repeated = False
        repeat_at = None
        deadline = expiry_start + self.c["set_timeout_seconds"] + 8
        poll = 0
        while True:
            require(time.monotonic() < deadline, "natural nft set expiry deadline exceeded")
            time.sleep(0.1)
            if not repeated and time.monotonic() - expiry_start >= self.c["set_timeout_seconds"] / 2:
                before, _ = self.snapshot_table(profile + "-expiry-repeat-before")
                answer = exchange(self.c["host"], self.c["listener_port"], protocol, name, typ, self.c["query_timeout_seconds"])
                after, _ = self.snapshot_table(profile + "-expiry-repeat-after")
                require(after == before, "expiry repeat unexpectedly queried an upstream")
                repeated, repeat_at = True, time.monotonic() - expiry_start
            _, learned = self.snapshot_table(f"{profile}-expiry-{poll:04d}")
            observed = time.monotonic()
            largest_poll_gap = max(largest_poll_gap, observed - previous_observation)
            previous_observation = observed
            if not (expected & learned[version]):
                break
            last_present, poll = observed, poll + 1
            self.healthy()
        require(repeated, "expiry repeat was not exercised before element disappearance")
        require(largest_poll_gap + 1 < repeat_at,
                "NFT observation gap cannot distinguish original expiry from a repeated-write reset", Blocked)
        require(observed - expiry_start <= self.c["set_timeout_seconds"] + largest_poll_gap + 1,
                "cached repeat appears to extend original nft expiry deadline")
        self.result["measurements"].append(dict(kind="nft_expiry", profile=profile,
                                               configured_timeout_seconds=self.c["set_timeout_seconds"],
                                               last_present_seconds=last_present-expiry_start,
                                               first_absent_seconds=observed-expiry_start,
                                               cached_repeat_seconds=repeat_at, largest_poll_gap_seconds=largest_poll_gap,
                                               original_deadline_preserved_with_observation_margin=True))
        self.check(profile + "-nft-lifecycle", "passed", "Delete, cached re-add, repeated-write deadline preservation and natural expiry bounded by monotonic snapshots")
        if self.pages_script:
            self.pages(profile)
        self.stop_app(profile + "-real")

    def helper(self, args, timeout=30):
        command = " ".join(shlex.quote(str(arg)) for arg in args)
        script = self.guard() + ("sh -c 'printf \"%s\\n\" \"$$\" > \"$1/cgroup.procs\"; shift; ulimit -f 256; exec env GOMEMLIMIT=16MiB GOMAXPROCS=2 \"$@\"' sh \"$CG/helpers\" " + command + "\n")
        return self.remote(script, timeout)

    def benchmark(self):
        b, c = self.c["benchmark"], self.c
        if not b["enabled"]:
            self.check("controlled-benchmark", "skipped", "Disabled explicitly in private config")
            self.result["limitations"].append("Router controlled benchmark was disabled for this run.")
            return
        for branch, port in (("cn", c["mock_port"]), ("foreign", c["foreign_mock_port"])):
            self.remote(self.guard() + f'''sh -c 'printf "%s\\n" "$$" > "$1/cgroup.procs"; shift; ulimit -f 256; exec env GOMEMLIMIT=16MiB GOMAXPROCS=2 "$@"' sh "$CG/helpers" "$R/dnsbench" -mode mock -addr 127.0.0.1:{port} -branch {branch} > "$R/mock-{branch}.log" 2>&1 < /dev/null &
''')
            for network in ("udp", "tcp"):
                deadline = time.monotonic() + 5
                while True:
                    rows = self.helper([self.root + "/dnsbench", "-mode", "probe", "-addr", "127.0.0.1:" + str(port),
                                        "-net", network, "-names", "cn-site.test", "-timeout", "500ms"])
                    row = json.loads(rows)
                    if not row.get("error") and row.get("id_ok"):
                        break
                    require(time.monotonic() < deadline, "mock upstream readiness failed")
                    time.sleep(0.1)
        def trial(profile, cache, network, concurrency, label, count):
            common = [self.root + "/dnsbench", "-mode", "load", "-addr", c["host"] + ":" + str(c["listener_port"]),
                      "-net", network, "-c", str(concurrency), "-file", self.root + "/queries.txt", "-expect-mock"]
            if cache == "hot":
                prewarm = self.helper(common + ["-n", "20"])
                self.raw(label + "-prewarm.json", prewarm)
                require(json.loads(prewarm)["errors"] == 0, "benchmark prewarm failed")
            shared_workload = label.replace("-" + profile + "-", "-paired-")
            args = common + ["-n", str(count), "-prefix", self.owner[:12] + "-" + shared_workload]
            if cache == "cold":
                args.append("-unique")
            cpu_before = self.remote(self.guard() + 'cat "$CG/app/cpu.stat"\n')
            result = self.helper(args, timeout=min(c["watchdog_seconds"], 180))
            cpu_after = self.remote(self.guard() + 'cat "$CG/app/cpu.stat"\n')
            self.raw(label + ".json", result)
            self.raw(label + "-cpu-before.txt", cpu_before)
            self.raw(label + "-cpu-after.txt", cpu_after)
            row = json.loads(result)
            require(row["queries"] == count and row["errors"] == 0 and row["active_workers"] == concurrency,
                    "controlled benchmark response/concurrency assertion failed")
            row.update(profile=profile, cache=cache)
            self.healthy()
            return row
        # Calibration has its own evidence and is excluded from formal statistics.
        # Use the largest count needed by any profile for each paired matrix cell.
        import math
        fixed = {}
        for profile in ("baseline", "full", "minimal"):
            for cache in ("hot", "cold"):
                self.start_app(profile, "bench.yaml")
                for network in ("udp", "tcp"):
                    for concurrency in b["concurrency"]:
                        label = f"calibration-{profile}-{cache}-{network}-c{concurrency}"
                        row = trial(profile, cache, network, concurrency, label, b["queries"])
                        self.result["measurements"].append(dict(kind="calibration", excluded_from_formal=True, **row))
                        key = cache, network, concurrency
                        count = max(b["queries"], math.ceil(row["qps"] * (b["minimum_seconds"] + 1)))
                        fixed[key] = max(fixed.get(key, 0), min(count, 100000))
                self.stop_app(label)
        self.raw("fixed-counts.json", (json.dumps([{ "cache": key[0], "network": key[1], "concurrency": key[2], "queries": count}
                    for key, count in fixed.items()], indent=2) + "\n").encode())
        for round_index in range(b["rounds"]):
            profiles = ["baseline", "full", "minimal"]
            if round_index % 2:
                profiles.reverse()
            for profile in profiles:
                for cache in ("hot", "cold"):
                    self.start_app(profile, "bench.yaml")
                    for network in ("udp", "tcp"):
                        for concurrency in b["concurrency"]:
                            label = f"bench-r{round_index}-{profile}-{cache}-{network}-c{concurrency}"
                            row = trial(profile, cache, network, concurrency, label, fixed[(cache, network, concurrency)])
                            row.update(kind="controlled_dns", round=round_index,
                                       eligible_throughput=row["seconds"] >= b["minimum_seconds"])
                            self.result["measurements"].append(row)
                    self.stop_app(label)
        self.remote(self.guard() + '''while read -r pid; do kill -TERM "$pid"; done < "$CG/helpers/cgroup.procs"
i=0
while [ -n "$(cat "$CG/helpers/cgroup.procs")" ] && [ "$i" -lt 20 ]; do sleep 0.1; i=$((i+1)); done
[ -z "$(cat "$CG/helpers/cgroup.procs")" ]
''')
        self.check("controlled-benchmark", "passed", "Fixed-count hot/cold UDP/TCP matrix; alternating profiles; all mock responses and requested concurrency verified")

    def pages(self, profile):
        from concurrent.futures import ThreadPoolExecutor
        c = self.c
        self.pages_root.mkdir(mode=0o700, exist_ok=True)
        page_check = dict(name=profile + "-pages-and-dns-replay", status="failed", detail="Page stage interrupted")
        self.page_result["checks"].append(page_check)
        with socket.socket() as stream:
            stream.bind(("127.0.0.1", 0))
            local_port = stream.getsockname()[1]
        before, _ = self.snapshot_table(profile + "-pages-before")
        args = [self.root + "/routerproxy", "-listen", "127.0.0.1:" + str(c["proxy_port"]),
                "-dns", "127.0.0.1:" + str(c["listener_port"]),
                "-cn-site", self.root + "/cn-site.txt", "-cn-ip", self.root + "/cn-ip.txt",
                "-direct-interface", c["direct_interface"], "-tunnel-interface", c["wireguard_interface"],
                "-direct-mark", str(c["direct_mark"]), "-tunnel-mark", str(c["foreign_mark"])]
        command = " ".join(map(shlex.quote, args))
        self.remote(self.guard() + '''sh -c 'printf "%s\\n" "$$" > "$1/cgroup.procs"; shift; ulimit -f 256; exec env GOMEMLIMIT=16MiB GOMAXPROCS=2 "$@"' sh "$CG/helpers" '''
                    + command + ' > "$R/' + profile + '-proxy.log" 2>&1 < /dev/null &\n')
        tunnel = subprocess.Popen(self.ssh[:-1] + ["-N", "-o", "ExitOnForwardFailure=yes", "-L",
                                  f"127.0.0.1:{local_port}:127.0.0.1:{c['proxy_port']}", self.ssh[-1]],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while True:
                log = self.remote(self.guard() + f'cat "$R/{profile}-proxy.log"\n')
                if any(json.loads(line).get("kind") == "ready" for line in log.splitlines() if line.startswith(b"{")):
                    break
                require(time.monotonic() < deadline, "router page proxy readiness timed out")
                time.sleep(0.2)
            require(tunnel.poll() is None, "page SSH forward did not start")
            output = self.pages_root / profile
            completed = subprocess.run([sys.executable, str(self.pages_script), "--proxy", f"http://127.0.0.1:{local_port}",
                                        "--profile", profile, "--output", str(output), "--commit", self.commit], timeout=300)
            summary = json.loads(regular(output / "results.json"))
            self.page_result["measurements"].extend(summary.get("measurements", []))
            log = self.remote(self.guard() + f'cat "$R/{profile}-proxy.log"\n')
            self.raw(profile + "-proxy.ndjson", log)
            with (output / "proxy.ndjson").open("xb") as stream:
                stream.write(log)
            self.page_result["artifacts"].append(dict(path=profile + "/proxy.ndjson"))
            rows = [json.loads(line) for line in log.splitlines()]
            dns = [row for row in rows if row.get("kind") == "dns"]
            dials = [row for row in rows if row.get("kind") == "origin_dial"]
            require(dns and dials, "page proxy recorded no router DNS/origin activity")
            require(all(row.get("ok") and not row.get("error") for row in dns), "page proxy DNS errors recorded")
            after, _ = self.snapshot_table(profile + "-pages-after")
            require(after["website_direct"] > before["website_direct"], "page direct egress counter did not increase")
            if any(row.get("route") == "tunnel" and row.get("ok") for row in dials):
                require(after["website_foreign"] > before["website_foreign"], "successful tunnel dial lacks tunnel egress counter")
            for row in dials:
                expected = "direct" if row["route"] == "direct" else "foreign"
                require(row["interface"] == c["direct_interface" if expected == "direct" else "wireguard_interface"]
                        and row["mark"] == c["direct_mark" if expected == "direct" else "foreign_mark"],
                        "proxy origin interface/mark assertion failed")
            self.page_result["measurements"].append(dict(kind="proxy_dns", profile=profile, queries=len(dns),
                    errors=sum(not row.get("ok") for row in dns), max_ms=max(row["elapsed_ms"] for row in dns),
                    origin_attempts=len(dials), origin_failures=sum(not row.get("ok") for row in dials),
                    direct_packets=after["website_direct"]-before["website_direct"],
                    tunnel_packets=after["website_foreign"]-before["website_foreign"]))
            require(completed.returncode == 0 and summary.get("status") == "passed", "page controller did not pass")
            hosts = sorted({row["host"] for row in dials if row.get("cn_site")})[:40]
            require(hosts, "page run produced no CN-site hosts for DNS/NFT replay")
            # Exact domain classification comes from the Go proxy's shared matcher.
            expected = {4: set(), 6: set()}
            for name in hosts:
                for typ in (1, 28):
                    answer = exchange(c["host"], c["listener_port"], "udp", name, typ, c["query_timeout_seconds"], typ == 1)
                    for row in answer["addresses"]:
                        expected[ipaddress.ip_address(row["ip"]).version].add(row["ip"])
            queries = [(name, typ) for _ in range(4) for name in hosts for typ in (1, 28)]
            for batch in range(4):
                self.flush()
                counters, _ = self.snapshot_table(f"{profile}-page-replay-{batch}-before")
                start = time.monotonic()
                def replay(query):
                    name, typ = query
                    return exchange(c["host"], c["listener_port"], "udp", name, typ, c["query_timeout_seconds"], typ == 1)
                with ThreadPoolExecutor(max_workers=16) as pool:
                    answers = list(pool.map(replay, queries))
                seconds = time.monotonic() - start
                after, learned = self.snapshot_table(f"{profile}-page-replay-{batch}-after")
                require(after == counters, "page cached replay generated an upstream/website packet")
                require(expected[4] <= learned[4] and expected[6] <= learned[6], "page cached replay failed to rebuild every answer IP")
                latencies = sorted(row["elapsed_ms"] for row in answers)
                measure = dict(kind="page_dns_replay", profile=profile, batch=batch, hosts=len(hosts), queries=len(queries),
                               concurrency=16, errors=0, seconds=seconds, qps=len(queries)/seconds,
                               p50_ms=latencies[int((len(latencies)-1)*.5)], p95_ms=latencies[int((len(latencies)-1)*.95)],
                               p99_ms=latencies[int((len(latencies)-1)*.99)], learned4=len(learned[4]), learned6=len(learned[6]))
                self.raw(f"{profile}-page-replay-{batch}-answers.json", (json.dumps(answers, indent=2) + "\n").encode())
                self.page_result["measurements"].append(measure)
                self.healthy()
            page_check.update(status="passed", detail="QQ/Taobao first/repeat, proxy DNS/egress guards and four bounded 16-worker CN-site cached replay batches passed")
            self.check(profile + "-pages", "passed", page_check["detail"])
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait()
            self.remote(self.guard() + '''while read -r pid; do kill -TERM "$pid" 2>/dev/null || :; done < "$CG/helpers/cgroup.procs"
sleep 0.2
[ -z "$(cat "$CG/helpers/cgroup.procs")" ]
''')

    def cleanup(self):
        self.remote(self.cleanup_script(), 30)
        after = self.read_state()
        before_summary, after_summary = self.summarize_state(self.baseline), self.summarize_state(after)
        self.raw("cleanup-state.json", (json.dumps(after_summary, indent=2) + "\n").encode())
        require(after["boot"] == self.baseline["boot"], "device rebooted during testing")
        for key, value in before_summary["stable_sha256"].items():
            require(after_summary["stable_sha256"][key] == value, "cleanup baseline drift: " + key)
        require(after["kernel"].startswith(self.baseline["kernel"]), "kernel ring buffer wrapped; cannot prove absence of new failure")
        added = after["kernel"][len(self.baseline["kernel"]):]
        require(not re.search(r"(?i)(out of memory|oom-kill|invoked oom-killer|kernel panic|BUG:|Call Trace:|segfault|soft lockup|hung task)", added),
                "new kernel/resource failure during testing")
        port_hex = "|".join(f"{self.c[key]:04X}" for key in ("listener_port", "mock_port", "proxy_port", "foreign_mock_port"))
        cleanup_guard = ("set -eu\nR=" + shlex.quote(self.root) + "\nCG=" + shlex.quote(self.cg)
                         + "\nTABLE=" + self.table + "\n[ \"$(cat /proc/sys/kernel/random/boot_id)\" = " + shlex.quote(self.boot) + " ]\n")
        self.remote(cleanup_guard + f'''[ ! -d "$CG" ]
[ ! -e {shlex.quote(self.lock)} ]
! nft list table inet "$TABLE" >/dev/null 2>&1
! awk '$2 ~ /:({port_hex})$/ {{found=1}} END{{exit !found}}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6
# Stop this run's sleeping watchdog after scoped resources have gone.
if [ -f "$R/watchdog.pid" ]; then
 pid=$(cat "$R/watchdog.pid")
 if [ -r "/proc/$pid/stat" ] && [ "$(awk '{{print $22}}' "/proc/$pid/stat")" = "$(cat "$R/watchdog.start")" ] && tr '\\000' ' ' < "/proc/$pid/cmdline" | grep -F "$R" >/dev/null; then kill -TERM "$pid"; fi
fi
''')
        self.check("cleanup", "passed", "Owned resources removed; boot/config/resolver/routes/addresses/WG/nft structure preserved; no new kernel failure")
        # Cleanup script and uploaded files are this run's exact directory only.
        for name in self.program_logs + ["mock-cn.log", "mock-foreign.log"]:
            data = self.remote(cleanup_guard + 'if [ -f "$R/.owner" ] && [ "$(cat "$R/.owner")" = ' + self.owner + ' ] && [ -f "$R/' + name + '" ]; then cat "$R/' + name + '"; fi\n')
            if data:
                self.raw("process-" + name, data)
        self.remote(cleanup_guard + 'if [ -d "$R" ]; then [ ! -L "$R" ] && [ "$(cat "$R/.owner")" = ' + self.owner + ' ]; rm -rf "$R"; fi\n')
        self.deployed = False

    def execute(self, run):
        try:
            self.preflight()
            if not run:
                self.check("execution", "skipped", "Read-only preflight requested; no deployment or runtime test performed")
                self.result["limitations"].append("Preflight-only; all runtime and cleanup stages remain unexecuted.")
                self.result["status"] = "blocked"
                return
            self.deploy()
            self.benchmark()
            for profile in ("full", "minimal"):
                self.real_queries(profile)
            self.result["status"] = "passed" if self.c["benchmark"]["enabled"] else "blocked"
            if not self.c["benchmark"]["enabled"]:
                self.check("required-controlled-benchmark", "blocked", "Complete router plan requires the controlled matrix; explicitly disabled in private config")
        except Blocked as error:
            self.check("prerequisites", "blocked", str(error))
            self.result["status"] = "blocked"
        except (Failed, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            # Errors never include remote stdout/stderr, SSH key data or config values.
            detail = str(error) if isinstance(error, Failed) else type(error).__name__ + " while executing controller"
            self.check("execution", "failed", detail)
            self.result["status"] = "failed"
        finally:
            if self.deployed:
                try:
                    self.cleanup()
                except (Failed, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                    self.check("cleanup", "failed", str(error) if isinstance(error, Failed) else type(error).__name__)
                    self.result["status"] = "failed"
                    self.result["limitations"].append("Cleanup could not be verified; owned remote watchdog will attempt scoped cleanup, and manual recovery may be required.")
            if self.page_result is not None:
                self.pages_root.mkdir(mode=0o700, exist_ok=True)
                self.page_result["status"] = "passed" if len([item for item in self.page_result["checks"] if item["status"] == "passed"]) == 2 else "failed"
                write_json(self.pages_root / "results.json", self.page_result)
            self.result["finished_at"] = datetime.now(timezone.utc).isoformat()
            write_json(self.out / "results.json", self.result)
            # Hash manifest is independent of its own content and is written once.
            files = sorted(p for p in self.out.rglob("*") if p.is_file() and not p.is_symlink())
            with (self.out / "SHA256SUMS").open("x") as stream:
                for path in files:
                    stream.write(digest(path.read_bytes()) + "  " + str(path.relative_to(self.out)) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--preflight-only", action="store_true")
    choice.add_argument("--run", action="store_true")
    parser.add_argument("--pages-script", type=Path)
    args = parser.parse_args(argv)
    require(re.fullmatch(r"[a-f0-9]{40}", args.commit), "exact 40-character commit required", Blocked)
    require(not args.output.exists(), "output already exists; evidence cannot be overwritten", Blocked)
    args.output.mkdir(parents=True, mode=0o700)
    try:
        repo = Path(__file__).resolve().parents[2]
        require(not args.config.resolve().is_relative_to(repo) and not args.config.resolve().is_relative_to(args.output.resolve()),
                "private config must be outside repository and evidence directory", Blocked)
        config = load_config(args.config)
        for name in ("ssh_identity", "ssh_known_hosts", "cn_site_file", "cn_ip_file"):
            resolved = Path(config[name]).resolve()
            require(not resolved.is_relative_to(repo) and not resolved.is_relative_to(args.output.resolve()),
                    "private input files must be outside repository and evidence directory", Blocked)
        bundle, binaries = load_bundle(args.artifacts, args.commit)
        if args.pages_script:
            regular(args.pages_script)
        controller = Controller(config, bundle, binaries, args.output, args.commit, args.pages_script)
    except (Blocked, OSError, ValueError, KeyError) as error:
        detail = str(error) if isinstance(error, Blocked) else type(error).__name__ + " while loading private prerequisites"
        write_json(args.output / "results.json", dict(schema_version=1, suite="router131", status="blocked",
                   source_commit=args.commit, checks=[dict(name="inputs", status="blocked", detail=detail)],
                   measurements=[], environment={}, limitations=["No SSH connection or target mutation performed."], artifacts=[]))
        return 2
    controller.execute(args.run)
    print(json.dumps(dict(suite="router131", status=controller.result["status"], output=str(args.output))))
    return {"passed": 0, "failed": 1, "blocked": 2}[controller.result["status"]]


if __name__ == "__main__":
    sys.exit(main())
