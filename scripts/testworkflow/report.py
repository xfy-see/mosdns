#!/usr/bin/env python3
"""Render current-run evidence without converting missing coverage into a pass."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any
from urllib.parse import quote

STATUSES = {"passed", "failed", "blocked", "skipped"}
OPTIONAL_SUITES = ("router131", "pages131")
SECRET_KEY = re.compile(r"password|secret|token|private.?key|authorization|credential", re.I)
SHA = re.compile(r"[0-9a-f]{40}\Z")
SAFE_ENV = {
    "kind", "runner_os", "kernel", "architecture", "go_version", "network", "target",
    "isolation", "deployment", "cleanup", "boot_id", "cpu_count", "memory_limit_mib",
    "source_revision", "profiles", "duration_s", "started_at", "finished_at", "goarch",
    "host", "synthetic", "namespace", "cgroup", "baseline_commit", "site_list_sha256",
    "profile", "race", "memory_limit_bytes", "cpu_quota", "worker_count", "sample_count",
    "owner", "direct_dns", "foreign_dns", "direct_interface", "wireguard_interface", "cn_site_sha256",
    "cn_site_lines", "cn_ip_sha256", "cn_ip_prefixes", "bundle_sha256", "configured_limits",
    "memory_available_kib", "stable_sha256", "kernel_sha256", "cgroup_limits_available", "fixture_kind",
    "domain_count", "memory_max_bytes", "pids_max", "GOMAXPROCS", "GOMEMLIMIT", "binaries", "proxy",
}


def clean(value: Any) -> Any:
    """Do not copy credential fields or PEM private keys into the public summary."""
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items() if not SECRET_KEY.search(str(k))}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                       "[redacted private key]", value, flags=re.S)
        value = re.sub(r"(?i)(authorization:\s*(?:bearer|basic)\s+)\S+", r"\1[redacted]", value)
        value = re.sub(r"(?i)((?:password|token|secret)\s*[=:]\s*)[^\s,;]+", r"\1[redacted]", value)
        value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def safe_file(root: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or "\\" in relative or "\x00" in relative:
        return None
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    candidate = root.joinpath(*path.parts)
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    if candidate.is_symlink() or not resolved.is_file():
        return None
    return resolved


def artifact(root: Path, output: Path, relative: Any) -> dict[str, Any] | None:
    path = safe_file(root, relative)
    if path is None:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": path.relative_to(root.resolve()).as_posix(),
            "href": quote(os.path.relpath(path, output), safe="/.-_"),
            "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def normalize_suite(data: dict[str, Any], path: str, commit: str) -> dict[str, Any]:
    name = data.get("suite")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,120}", name):
        name = "invalid:" + path
    checks = []
    for check in data.get("checks", []) if isinstance(data.get("checks"), list) else []:
        if isinstance(check, dict):
            status = check.get("status", "failed")
            checks.append({"name": str(check.get("name", "unnamed check")),
                           "status": status if isinstance(status, str) and status in STATUSES else "failed",
                           "detail": str(clean(check.get("detail", "")))})
    status = data.get("status", "failed")
    if not isinstance(status, str) or status not in STATUSES:
        checks.append({"name": "result schema", "status": "failed", "detail": "Unknown suite status"})
        status = "failed"
    if data.get("source_commit") != commit:
        checks.append({"name": "source binding", "status": "failed",
                       "detail": "Suite source_commit does not match this report's commit"})
        status = "failed"
    if any(check["status"] == "failed" for check in checks):
        status = "failed"
    elif status == "passed" and any(check["status"] == "blocked" for check in checks):
        status = "blocked"
    environment = data.get("environment", {})
    environment = {k: v for k, v in environment.items() if k in SAFE_ENV} if isinstance(environment, dict) else {}
    measurements = data.get("measurements", [])
    limitations = data.get("limitations", [])
    return {"suite": name, "status": status, "source_commit": data.get("source_commit"),
            "checks": checks, "measurements": clean(measurements) if isinstance(measurements, list) else [],
            "environment": clean(environment),
            "limitations": [str(clean(v)) for v in limitations] if isinstance(limitations, list) else [],
            "artifacts": data.get("artifacts", []) if isinstance(data.get("artifacts"), list) else [],
            "evidence_path": path}


def go_events(path: Path, relative: str) -> dict[str, Any] | None:
    counts: Counter[str] = Counter()
    started: set[str] = set()
    finished: set[str] = set()
    malformed = 0
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Go writes module download/toolchain notices to stderr, which
                # validate.py deliberately retains alongside JSON stdout.
                malformed += int(line.lstrip().startswith("{"))
                continue
            if not isinstance(event, dict) or "Action" not in event or "Package" not in event:
                continue
            action, package = event["Action"], event["Package"]
            if action == "start":
                started.add(str(package))
            if action in ("pass", "fail", "skip"):
                counts[("test_" if event.get("Test") else "package_") + action] += 1
                if not event.get("Test"):
                    finished.add(str(package))
    if not counts and not started:
        return None
    pending = sorted(started - finished)
    status = "failed" if counts["test_fail"] or counts["package_fail"] or malformed else "blocked" if pending else "passed"
    return {"path": relative, "status": status, "counts": dict(counts),
            "unfinished_packages": pending, "malformed_lines": malformed,
            "count_note": "Test event counts include nested subtests; package skips can mean no test files."}


def binary_rows(data: dict[str, Any], path: Path, root: Path, commit: str) -> list[dict[str, Any]]:
    rows = []
    files = data.get("files")
    if isinstance(files, dict):
        entries = [(name, item) for name, item in files.items() if isinstance(item, dict)]
    elif isinstance(data.get("artifacts"), list) and "target" in data:
        entries = [(item.get("file", ""), item) for item in data["artifacts"] if isinstance(item, dict)]
    else:
        return rows
    remote_build = data.get("remote_build", {})
    remote_build = remote_build if isinstance(remote_build, dict) else {}
    target = data.get("target", {})
    target = target if isinstance(target, dict) else {}
    bound = data.get("source_commit") or remote_build.get("commit")
    if not bound and isinstance(data.get("version"), str) and data["version"].startswith("git-"):
        bound = data["version"][4:]
    arch = str(data.get("goarch") or target.get("goarch", "unknown"))
    for filename, item in entries:
        size = item.get("bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            continue
        profile = item.get("profile")
        if not profile:
            profile = next((p for p in ("baseline", "minimal", "full") if p in str(filename)), "helper")
        profile = str(profile)
        source = item.get("source_commit", bound)
        relative = (path.parent.relative_to(root) / str(filename)).as_posix()
        candidate = safe_file(root, relative)
        verified = "failed missing binary" if isinstance(files, dict) else "manifest only"
        if candidate is not None:
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            verified = "verified" if candidate.stat().st_size == size and digest == item.get("sha256") else "failed hash/size"
        if source != commit and profile != "baseline":
            verified = "failed source binding"
        if profile == "baseline" and data.get("baseline_commit") and source != data["baseline_commit"]:
            verified = "failed baseline binding"
        rows.append({"profile": profile, "architecture": arch, "file": str(filename), "bytes": size,
                     "mib": round(size / 1048576, 3), "sha256": str(item.get("sha256", "")),
                     "source_commit": source, "verification": verified, "manifest": path.relative_to(root).as_posix()})
    return rows


def collect(root: Path, output: Path, commit: str, required: list[str]) -> dict[str, Any]:
    root, output = root.resolve(), output.resolve()
    suites: dict[str, dict[str, Any]] = {}
    logs, binaries, evidence = [], [], set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or output in path.parents:
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue
        relative = path.relative_to(root).as_posix()
        if path.suffix in (".json", ".jsonl"):
            # Large go test logs are streamed; suite documents and manifests are bounded.
            data = None
            if path.stat().st_size <= 8 * 1024 * 1024:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            if isinstance(data, dict) and data.get("schema_version") == 1 and "suite" in data:
                suite = normalize_suite(data, relative, commit)
                name = suite["suite"]
                if name in suites:
                    suite["status"] = "failed"
                    suite["checks"].append({"name": "duplicate suite", "status": "failed",
                                            "detail": "More than one result document supplied for this suite"})
                suites[name] = suite
                evidence.add(relative)
                for item in suite.pop("artifacts"):
                    relative_artifact = item.get("path") if isinstance(item, dict) else item
                    scoped = None
                    if isinstance(relative_artifact, str):
                        local = (path.parent.relative_to(root) / relative_artifact).as_posix()
                        scoped = local if safe_file(root, local) else relative_artifact if safe_file(root, relative_artifact) else None
                    if scoped:
                        evidence.add(scoped)
                        if isinstance(item, dict) and ("sha256" in item or "bytes" in item):
                            actual = artifact(root, output, scoped)
                            if actual is None or any(item[key] != actual[key] for key in ("sha256", "bytes") if key in item):
                                suite["checks"].append({"name": "artifact identity", "status": "failed",
                                                        "detail": "Raw artifact differs from its suite hash/size"})
                                suite["status"] = "failed"
                    else:
                        suite["checks"].append({"name": "artifact path", "status": "failed",
                                                "detail": "Artifact is missing or escapes the evidence directory"})
                        suite["status"] = "failed"
            elif isinstance(data, dict):
                rows = binary_rows(data, path, root, commit)
                if rows:
                    binaries.extend(rows)
                    evidence.add(relative)
                elif "Action" in data and "Package" in data:
                    events = go_events(path, relative)
                    if events:
                        logs.append(events)
                        evidence.add(relative)
            else:
                events = go_events(path, relative)
                if events:
                    logs.append(events)
                    evidence.add(relative)
    for name in sorted(set(required) | set(OPTIONAL_SUITES)):
        if name not in suites:
            requested = name in required
            suites[name] = {"suite": name, "status": "blocked" if requested else "skipped",
                            "source_commit": commit, "checks": [], "measurements": [], "environment": {},
                            "limitations": ["Requested suite produced no result document" if requested else "Not requested in this run"],
                            "evidence_path": None}
    for suite in suites.values():
        if suite["suite"].startswith(("unit-", "race-")) and suite["status"] == "passed":
            parent = PurePosixPath(suite["evidence_path"]).parent
            if not any(PurePosixPath(log["path"]).parent == parent for log in logs):
                suite["status"] = "failed"
                suite["checks"].append({"name": "Go test evidence", "status": "failed",
                                        "detail": "Passed Go suite has no readable Go JSON event log"})
    artifacts = [item for relative in sorted(evidence) if (item := artifact(root, output, relative)) is not None]
    binaries = list({(b["architecture"], b["profile"], str(b["source_commit"]), b["sha256"], b["bytes"]): b
                     for b in reversed(binaries)}.values())
    bad = any(s["status"] != "passed" if s["suite"] in required else s["status"] == "failed" for s in suites.values())
    bad = bad or any(log["status"] != "passed" for log in logs) or any(str(b["verification"]).startswith("failed") for b in binaries)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    links = {}
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        links["source"] = f"https://github.com/{repository}/tree/{commit}"
        if run.isdigit():
            links["actions_run"] = f"https://github.com/{repository}/actions/runs/{run}"
    return {"schema_version": 1, "source_commit": commit, "status": "failed" if bad else "passed",
            "required_suites": required, "suites": list(suites.values()), "go_test_logs": logs,
            "binaries": binaries, "artifacts": artifacts, "links": links,
            "limitations": [
                "Hosted network namespace measurements use synthetic DNS responses and do not prove real router, WireGuard or public website behavior.",
                "Only current-run evidence is included. Missing optional router/page coverage is displayed as skipped.",
                "Successful exchange latency excludes failures; QPS uses successes divided by total row duration. Short samples do not establish throughput improvement.",
                "Raw artifacts must already be sanitized by their producer; summary redaction is not a replacement for excluding credentials from logs."]}


def scalar(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return "—" if value is None else str(value)


def md_text(value: Any) -> str:
    text = html.escape(scalar(value)).replace("\\", "\\\\")
    for character in "`*_[]{}()!#~|":
        text = text.replace(character, "\\" + character)
    return text.replace("\r", " ").replace("\n", "<br>")


def performance_comparisons(measurements: list[dict[str, Any]]) -> list[list[Any]]:
    """Compare only error-free matched rows long enough for a rate observation."""
    groups = {}
    for row in measurements:
        if row.get("excluded_from_formal") or row.get("kind") == "calibration":
            continue
        key = tuple(scalar(row.get(k)) for k in ("round", "cache")) + (scalar(row.get("network", row.get("protocol"))),) + tuple(scalar(row.get(k)) for k in ("concurrency", "queries", "unique", "nft_writes_enabled"))
        groups.setdefault(key, {})[str(row.get("profile"))] = row
    comparisons = []
    for _, profiles in groups.items():
        baseline = profiles.get("baseline")
        if not baseline:
            continue
        for profile in ("full", "minimal"):
            row = profiles.get(profile)
            if not row:
                continue
            valid = all(isinstance(r.get("seconds"), (int, float)) and r["seconds"] >= 2
                        and isinstance(r.get("qps"), (int, float)) and r["qps"] > 0
                        and r.get("errors") == 0 and r.get("rate_comparison_valid", True) is not False
                        and r.get("eligible_throughput", True) is not False
                        for r in (baseline, row))
            delta = f"{(row['qps'] / baseline['qps'] - 1) * 100:+.2f}%" if valid else "not compared (short/error sample)"
            comparisons.append([row.get("round"), row.get("cache"), row.get("network", row.get("protocol")), row.get("concurrency"),
                                profile, baseline.get("qps"), row.get("qps"), delta,
                                baseline.get("p95_ms"), row.get("p95_ms")])
    return comparisons


def table(headers: list[str], rows: list[list[Any]], html_mode: bool = False) -> str:
    if html_mode:
        return "<div class=table-scroll><table><thead><tr>" + "".join("<th scope=col>" + html.escape(h) + "</th>" for h in headers) + "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + html.escape(scalar(v)) + "</td>" for v in row) + "</tr>" for row in rows) + "</tbody></table></div>"
    return "| " + " | ".join(md_text(h) for h in headers) + " |\n| " + " | ".join("---" for _ in headers) + " |\n" + "\n".join("| " + " | ".join(md_text(v) for v in row) + " |" for row in rows)


def render(result: dict[str, Any], html_mode: bool = False) -> str:
    parts = []
    def heading(title: str, level: int = 2) -> None:
        parts.append(f"<h{level}>{html.escape(title)}</h{level}>" if html_mode else "#" * level + " " + title)
    def paragraph(value: Any) -> None:
        parts.append("<p>" + html.escape(scalar(value)) + "</p>" if html_mode else md_text(value))
    heading("mosdns test plan report", 1)
    paragraph(f"Result: {result['status']} · source: {result['source_commit']}")
    for label, url in result["links"].items():
        parts.append(f'<p><a href="{html.escape(url, quote=True)}">{html.escape(label)}</a></p>' if html_mode else f"[{label}]({url})")
    heading("Coverage")
    parts.append(table(["Suite", "Status", "Checks", "Environment"], [[s["suite"], s["status"], len(s["checks"]), s["environment"]] for s in result["suites"]], html_mode))
    for suite in result["suites"]:
        heading(suite["suite"], 3)
        if suite["checks"]:
            parts.append(table(["Check", "Status", "Detail"], [[c["name"], c["status"], c["detail"]] for c in suite["checks"]], html_mode))
        measurements = [row for row in suite["measurements"] if isinstance(row, dict)]
        if measurements:
            comparisons = performance_comparisons(measurements)
            if comparisons:
                heading("Paired performance observations", 4)
                parts.append(table(["Round", "Cache", "Protocol", "Concurrency", "Profile", "Baseline QPS", "Profile QPS", "QPS change", "Baseline P95 ms", "Profile P95 ms"], comparisons, html_mode))
                paragraph("Comparisons require matched queries, an error-free sample and at least two seconds for both rows; two rounds describe this run without establishing statistical significance.")
            display_measurements = []
            for row in measurements:
                display = dict(row)
                resources = display.pop("resources", None)
                if isinstance(resources, dict):
                    for key in ("rss_peak_bytes", "hwm_peak_bytes", "process_cpu_seconds"):
                        if key in resources:
                            display[key] = resources[key]
                display_measurements.append(display)
            keys = list(dict.fromkeys(key for row in display_measurements for key in row))
            parts.append(table(keys, [[row.get(key) for key in keys] for row in display_measurements[:1000]], html_mode))
            if len(measurements) > 1000:
                paragraph("Display limited to 1,000 rows; results.json contains every measurement.")
        for limitation in suite["limitations"]:
            paragraph(limitation)
    if result["binaries"]:
        heading("Binary size and identity")
        parts.append(table(["Profile", "Architecture", "Source commit", "Bytes", "MiB", "SHA256", "Verification"], [[b[k] for k in ("profile", "architecture", "source_commit", "bytes", "mib", "sha256", "verification")] for b in result["binaries"]], html_mode))
        groups = {}
        for binary in result["binaries"]:
            groups.setdefault((binary["architecture"], binary["manifest"]), {})[binary["profile"]] = binary["bytes"]
        rows = []
        for (arch, _), sizes in groups.items():
            for before, after in (("baseline", "full"), ("baseline", "minimal"), ("full", "minimal")):
                if sizes.get(before, 0) > 0 and after in sizes:
                    saved = sizes[before] - sizes[after]
                    rows.append([arch, f"{before} → {after}", saved, f"{saved / sizes[before] * 100:.2f}%"])
        if rows:
            parts.append(table(["Architecture", "Comparison", "Bytes saved", "Size reduction"], rows, html_mode))
    if result["go_test_logs"]:
        heading("Go JSON event logs")
        parts.append(table(["Log", "Status", "Event counts", "Unfinished packages"], [[log["path"], log["status"], log["counts"], log["unfinished_packages"]] for log in result["go_test_logs"]], html_mode))
        paragraph("Test event counts include nested subtests. Package skips can indicate packages with no test files.")
    heading("Interpretation limits")
    for limitation in result["limitations"]:
        paragraph(limitation)
    heading("Raw evidence")
    for item in result["artifacts"]:
        label, href = item["path"], item["href"]
        suffix = f" · {item['bytes']} bytes · SHA256 {item['sha256']}"
        parts.append(f'<p><a href="{html.escape(href, quote=True)}">{html.escape(label)}</a>{html.escape(suffix)}</p>' if html_mode else f"[{md_text(label)}]({href}){suffix}")
    body = "\n\n".join(parts) + "\n"
    if not html_mode:
        return body
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>mosdns test report</title><style>body{font:16px/1.55 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#18212a;background:#fff}a{color:#075bb5}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #c6ced6;padding:.55rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f5}.table-scroll{overflow-x:auto}h2{margin-top:2rem}p{overflow-wrap:anywhere}@media(prefers-color-scheme:dark){body{color:#e5edf5;background:#111820}th{background:#203040}a{color:#7bbaff}th,td{border-color:#506070}}</style><body><main>' + body + '</main></body></html>\n'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--required-suites", default="")
    parser.add_argument("--github-summary", type=Path)
    args = parser.parse_args(argv)
    if not SHA.fullmatch(args.commit):
        parser.error("--commit must be a full lowercase 40-character Git SHA")
    root, output = args.input.resolve(), args.output.resolve()
    if not root.is_dir() or root == output:
        parser.error("--input must exist and --output must be a different directory")
    required = sorted(set(filter(None, (name.strip() for name in args.required_suites.split(",")))))
    result = collect(root, output, args.commit, required)
    output.mkdir(parents=True, exist_ok=True)
    markdown = render(result)
    (output / "results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output / "report.md").write_text(markdown, encoding="utf-8")
    (output / "report.html").write_text(render(result, True), encoding="utf-8")
    if args.github_summary:
        with args.github_summary.open("a", encoding="utf-8") as summary:
            summary.write(markdown)
    print(f"Report: {output / 'report.html'} ({result['status']})")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
