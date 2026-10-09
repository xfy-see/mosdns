#!/usr/bin/env python3
"""Package CI Go builds, or download and verify an exact GitHub Actions run.

The local list/build-wait/download commands never invoke a Go compiler or run
downloaded binaries. Authentication is delegated to gh; credentials are not
written into logs, manifests or receipts.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ".github/workflows/go-profiles.yml"
PIPELINE_INPUTS = (WORKFLOW, "benchmarks/build-go-profiles.py", "scripts/go-remote-build.py",
                   "tests/test_go_remote_build.py", "tests/test_release.py")
ARCHES = ("arm64", "amd64")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class BuildError(RuntimeError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def blob_sha1(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def regular_bytes(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise BuildError("expected regular file: " + str(path))
    return path.read_bytes()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def command(argv, cwd=ROOT):
    result = subprocess.run(argv, cwd=str(cwd), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if result.returncode:
        # Do not print subprocess output: a custom gh wrapper may reveal secrets.
        raise BuildError("command failed (exit %d): %s" % (result.returncode, argv[0]))
    return result.stdout


def safe_name(name):
    value = pathlib.PurePosixPath(name)
    if value.is_absolute() or not value.parts or any(p in (".", "..") for p in value.parts):
        raise BuildError("unsafe archive/input path")
    if value.as_posix() != name or "\\" in name or "\n" in name:
        raise BuildError("noncanonical archive/input path")
    return value


def artifact_name(arch, commit, attempt):
    return "mosdns-go-linux-%s-%s-attempt-%s" % (arch, commit, attempt)


def package(args):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise BuildError("package is reserved for GitHub Actions; no local compilation is performed")
    build = args.build_dir.resolve()
    manifest = json.loads(regular_bytes(build / "manifest.json"))
    if manifest.get("status") != "complete" or not manifest.get("source_and_snapshot_unchanged"):
        raise BuildError("build manifest is incomplete")
    target = manifest.get("target", {})
    arch = target.get("goarch")
    if target != {"goos": "linux", "goarch": arch, "cgo_enabled": False} or arch not in ARCHES:
        raise BuildError("only static Linux ARM64/amd64 builds are published")
    if not re.match(r"^go version go1\.26\.0\s", manifest.get("toolchain", {}).get("version", "")):
        raise BuildError("the publisher requires Go 1.26.0 exactly")
    commit = command(["git", "rev-parse", "HEAD"]).strip()
    if not SHA.fullmatch(commit) or commit != os.environ.get("GITHUB_SHA"):
        raise BuildError("checkout does not match GITHUB_SHA")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not REPOSITORY.fullmatch(repository):
        raise BuildError("invalid GitHub repository identity")
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    if run_id <= 0 or attempt <= 0:
        raise BuildError("invalid GitHub run identity")
    pipeline = {}
    pipeline_data = {}
    for name in PIPELINE_INPUTS:
        data = regular_bytes(ROOT / name)
        committed = subprocess.run(["git", "cat-file", "blob", commit + ":" + name],
                                   cwd=ROOT, stdout=subprocess.PIPE, check=True).stdout
        if data != committed:
            raise BuildError("pipeline input differs from selected commit: " + name)
        pipeline[name] = {"bytes": len(data), "sha256": sha256(data), "git_blob_sha1": blob_sha1(data)}
        pipeline_data[name] = data
    for name, record in manifest["source_inputs"].items():
        safe_name(name)
        data = regular_bytes(build / "snapshot" / name)
        committed = subprocess.run(["git", "cat-file", "blob", commit + ":" + name],
                                   cwd=ROOT, stdout=subprocess.PIPE, check=True).stdout
        if data != committed or {"bytes": len(data), "sha256": sha256(data)} != record:
            raise BuildError("frozen input differs from selected commit: " + name)
    manifest["remote_build"] = {
        "repository": repository, "commit": commit, "run_id": run_id, "run_attempt": attempt,
        "workflow_file": WORKFLOW, "event": os.environ["GITHUB_EVENT_NAME"],
        "ref": os.environ["GITHUB_REF"], "pipeline_inputs": pipeline,
        "required_tests": ["full", "minimal", "full-pprof", "race-full", "race-minimal"],
        "artifact_name": artifact_name(arch, commit, attempt),
    }
    # Keep the original build record and frozen tree; publish a bound copy.
    dist = build / "dist"
    dist.mkdir(mode=0o700)
    write_json(dist / "manifest.json", manifest)
    for artifact in manifest["artifacts"]:
        name = artifact["file"]
        safe_name(name)
        data = regular_bytes(build / name)
        if {"bytes": len(data), "sha256": sha256(data)} != {k: artifact[k] for k in ("bytes", "sha256")}:
            raise BuildError("ELF differs from build manifest")
        with (dist / name).open("xb") as stream:
            stream.write(data)
        (dist / name).chmod(0o755)
    archive = dist / ("mosdns-go-linux-" + arch + ".tar.gz")
    files = {}
    for directory, directories, names in os.walk(build, followlinks=False):
        directories[:] = sorted(d for d in directories if pathlib.Path(directory) / d != dist)
        for name in names:
            path = pathlib.Path(directory) / name
            key = path.relative_to(build).as_posix()
            files[key] = regular_bytes(path)
    files["manifest.json"] = regular_bytes(dist / "manifest.json")
    files.update({"pipeline-inputs/" + name: data for name, data in pipeline_data.items()})
    with archive.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as bundle:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755 if name.startswith("mosdns-") else 0o644
                entry.mtime = 0
                bundle.addfile(entry, io.BytesIO(data))
    with (dist / "SHA256SUMS").open("x", encoding="utf-8") as stream:
        for path in sorted(dist.iterdir()):
            if path.name != "SHA256SUMS":
                stream.write(sha256(regular_bytes(path)) + "  " + path.name + "\n")
    print("published bundle: " + str(dist))


class GitHub:
    def __init__(self, args):
        self.repo = args.repo
        self.gh = shutil.which(args.gh)
        if not self.gh:
            raise BuildError("GitHub CLI is missing; install gh or pass --gh /path/to/gh")

    def api(self, path):
        return json.loads(command([self.gh, "api", "--hostname", "github.com", "repos/" + self.repo + "/" + path]))

    def run(self, run_id):
        return self.api("actions/runs/" + str(run_id))

    def runs(self, commit, event=None):
        query = "?per_page=100&head_sha=" + commit
        if event:
            query += "&event=" + event
        return self.api("actions/workflows/go-profiles.yml/runs" + query)["workflow_runs"]


def validate_run(run, args, complete=True):
    if run.get("head_sha") != args.commit:
        raise BuildError("run does not match the requested commit")
    if run.get("repository", {}).get("full_name", "").lower() != args.repo.lower():
        raise BuildError("run belongs to another repository")
    if run.get("path", "").split("@")[0] != WORKFLOW:
        raise BuildError("run belongs to another workflow")
    if complete and (run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise BuildError("only fully successful completed runs can be downloaded")


def list_runs(args, gh):
    rows = gh.runs(args.commit)
    for run in rows[:args.limit]:
        validate_run(run, args, complete=False)
    print(json.dumps([{
        "run_id": r["id"], "run_attempt": r["run_attempt"], "commit": r["head_sha"],
        "event": r["event"], "status": r["status"], "conclusion": r["conclusion"],
        "created_at": r["created_at"], "url": r["html_url"],
    } for r in rows[:args.limit]], indent=2))


def build_wait(args, gh):
    branch = gh.api("git/ref/heads/" + quote(args.ref, safe="/"))
    if branch.get("object", {}).get("sha") != args.commit:
        raise BuildError("branch HEAD differs from requested commit; refusing dispatch")
    request = uuid.uuid4().hex
    title = "Go profiles " + args.commit + " " + request
    command([gh.gh, "workflow", "run", "go-profiles.yml", "--repo", args.repo,
             "--ref", args.ref, "-f", "expected_commit=" + args.commit, "-f", "request_id=" + request])
    print("dispatched exact commit " + args.commit + "; request " + request, flush=True)
    deadline = time.monotonic() + args.timeout
    run_id = None
    previous = None
    while time.monotonic() < deadline:
        if run_id is None:
            matches = [r for r in gh.runs(args.commit, "workflow_dispatch") if r.get("display_title") == title]
            if len(matches) > 1:
                raise BuildError("multiple runs matched one dispatch identifier")
            if matches:
                run_id = matches[0]["id"]
        if run_id is not None:
            run = gh.run(run_id)
            validate_run(run, args, complete=False)
            status = (run["status"], run.get("conclusion"))
            if status != previous:
                print("run %s: %s %s %s" % (run_id, status[0], status[1] or "", run["html_url"]), flush=True)
                previous = status
            if run["status"] == "completed":
                validate_run(run, args)
                return download_run(args, gh, run_id)
        time.sleep(min(args.poll, max(0, deadline - time.monotonic())))
    raise BuildError("waiting timed out; dispatched run is retained and was not cancelled")


def file_set(directory):
    result = {}
    for root, directories, names in os.walk(directory, followlinks=False):
        for name in directories:
            if (pathlib.Path(root) / name).is_symlink():
                raise BuildError("symlink directory in downloaded artifact")
        for name in names:
            path = pathlib.Path(root) / name
            result[path.relative_to(directory).as_posix()] = regular_bytes(path)
    return result


def verify_artifact(directory, arch, run, args, tree):
    files = file_set(directory)
    binary_names = ["mosdns-" + profile + "-linux-" + arch for profile in ("full", "minimal")]
    archive_name = "mosdns-go-linux-" + arch + ".tar.gz"
    expected = set(binary_names + ["manifest.json", archive_name, "SHA256SUMS"])
    if set(files) != expected:
        raise BuildError("unexpected or missing published files for " + arch)
    checksums = {}
    for line in files["SHA256SUMS"].decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if not match or match[2] in checksums:
            raise BuildError("invalid or duplicate SHA256SUMS entry")
        checksums[match[2]] = match[1]
    if set(checksums) != expected - {"SHA256SUMS"}:
        raise BuildError("SHA256SUMS file coverage mismatch")
    for name, expected_sha in checksums.items():
        if sha256(files[name]) != expected_sha:
            raise BuildError("download checksum mismatch: " + name)
    manifest = json.loads(files["manifest.json"])
    remote = manifest.get("remote_build", {})
    if (manifest.get("status") != "complete" or manifest.get("requested_profile") != "both"
            or manifest.get("pprof_full_only") is not False or manifest.get("compression") != "none"
            or not manifest.get("source_and_snapshot_unchanged")):
        raise BuildError("manifest does not describe a complete production build")
    if (remote.get("repository", "").lower() != args.repo.lower()
            or remote.get("commit") != args.commit or remote.get("run_id") != run["id"]
            or remote.get("run_attempt") != run["run_attempt"] or remote.get("workflow_file") != WORKFLOW
            or remote.get("artifact_name") != artifact_name(arch, args.commit, run["run_attempt"])):
        raise BuildError("manifest/run provenance mismatch")
    if remote.get("required_tests") != ["full", "minimal", "full-pprof", "race-full", "race-minimal"]:
        raise BuildError("required test contract mismatch")
    if manifest.get("target") != {"goos": "linux", "goarch": arch, "cgo_enabled": False}:
        raise BuildError("manifest target mismatch")
    if manifest.get("version") != "git-" + args.commit:
        raise BuildError("embedded version does not match selected commit")
    if not re.match(r"^go version go1\.26\.0\s", manifest.get("toolchain", {}).get("version", "")):
        raise BuildError("unexpected Go compiler version")
    artifacts = manifest.get("artifacts", [])
    if {a.get("file") for a in artifacts} != set(binary_names) or len(artifacts) != 2:
        raise BuildError("full/minimal manifest coverage mismatch")
    for artifact in artifacts:
        name = artifact["file"]
        data = files[name]
        profile = "minimal" if "-minimal-" in name else "full"
        tags = ["mosdns_minimal"] if profile == "minimal" else []
        if (artifact.get("profile") != profile or artifact.get("tags") != tags
                or artifact.get("sha256") != sha256(data) or artifact.get("bytes") != len(data)):
            raise BuildError("binary does not match manifest: " + name)
        machine = 183 if arch == "arm64" else 62
        if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(data[18:20], "little") != machine):
            raise BuildError("unexpected ELF format/architecture: " + name)
        # CGO=0 production binaries must not request a shared ELF interpreter.
        offset = int.from_bytes(data[32:40], "little")
        entry_size = int.from_bytes(data[54:56], "little")
        count = int.from_bytes(data[56:58], "little")
        if entry_size < 56 or count == 0 or offset + entry_size * count > len(data):
            raise BuildError("invalid ELF program header table")
        if any(int.from_bytes(data[offset + i * entry_size:offset + i * entry_size + 4], "little") == 3
               for i in range(count)):
            raise BuildError("binary requires a dynamic ELF interpreter")
    builds = [c for c in manifest.get("commands", []) if "build" in c.get("command", [])]
    if len(builds) != 2:
        raise BuildError("missing production build commands")
    for record in builds:
        argv = record["command"]
        required = ["-mod=readonly", "-trimpath", "-buildvcs=false", "-pgo=off", "-p=2",
                    "-ldflags=-s -w -buildid= -X main.version=git-" + args.commit]
        if record.get("exit_code") != 0 or any(flag not in argv for flag in required):
            raise BuildError("production build flags differ")
        tag_flags = [flag for flag in argv if flag.startswith("-tags")]
        binary = pathlib.PurePosixPath(argv[argv.index("-o") + 1]).name if "-o" in argv else ""
        if binary not in binary_names or tag_flags != (["-tags=mosdns_minimal"] if "-minimal-" in binary else []):
            raise BuildError("production profile tags differ")
        env = record.get("environment", {})
        if env.get("CGO_ENABLED") != "0" or env.get("GOOS") != "linux" or env.get("GOARCH") != arch:
            raise BuildError("production environment differs")
        if env.get("GOAMD64") != "v1" or env.get("GOARM64") != "v8.0":
            raise BuildError("production architecture baseline differs")
    inputs = manifest.get("source_inputs", {})
    if not inputs or sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()) != manifest.get("source_input_tree_sha256"):
        raise BuildError("source input tree digest mismatch")
    members = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(files[archive_name]), mode="r:gz") as bundle:
        for member in bundle:
            safe_name(member.name)
            total += member.size
            if not member.isfile() or member.name in members or total > 512 * 1024 * 1024 or len(members) >= 5000:
                raise BuildError("unsafe, duplicate or oversized bundle member")
            stream = bundle.extractfile(member)
            members[member.name] = stream.read()
    if members.get("manifest.json") != files["manifest.json"]:
        raise BuildError("archive manifest differs from standalone manifest")
    for name in binary_names:
        if members.get(name) != files[name]:
            raise BuildError("archive ELF differs from standalone ELF")
    if {n[len("snapshot/"):] for n in members if n.startswith("snapshot/")} != set(inputs):
        raise BuildError("archive frozen input coverage mismatch")
    for name, record in inputs.items():
        safe_name(name)
        data = members["snapshot/" + name]
        if {"bytes": len(data), "sha256": sha256(data)} != record or blob_sha1(data) != tree.get(name):
            raise BuildError("source input differs from selected Git commit: " + name)
    pipeline = remote.get("pipeline_inputs", {})
    if set(pipeline) != set(PIPELINE_INPUTS):
        raise BuildError("pipeline input coverage mismatch")
    for name, record in pipeline.items():
        data = members.get("pipeline-inputs/" + name, b"")
        if (record != {"bytes": len(data), "sha256": sha256(data), "git_blob_sha1": blob_sha1(data)}
                or record["git_blob_sha1"] != tree.get(name)):
            raise BuildError("pipeline input differs from selected Git commit: " + name)
    if set(manifest.get("production_dependencies", {})) != {"full", "minimal"}:
        raise BuildError("production dependency graph coverage mismatch")
    for profile, record in manifest["production_dependencies"].items():
        data = members.get(record.get("file"), b"")
        if not data or sha256(data) != record.get("sha256"):
            raise BuildError("dependency graph digest mismatch: " + profile)
    for name in binary_names:
        (directory / name).chmod(0o755)
    return {"arch": arch, "artifact": remote["artifact_name"], "files": checksums,
            "source_input_tree_sha256": manifest["source_input_tree_sha256"],
            "source_input_count": len(inputs), "verified_at": now()}


def verify_supplied(args):
    """Verify API/connector downloads without requiring a local gh executable."""
    run = json.loads(regular_bytes(args.run_json))
    validate_run(run, args)
    git_tree = json.loads(regular_bytes(args.tree_json))
    if git_tree.get("truncated"):
        raise BuildError("supplied Git tree listing is incomplete")
    tree = {item["path"]: item["sha"] for item in git_tree["tree"] if item["type"] == "blob"}
    if args.artifact_dir.is_symlink():
        raise BuildError("artifact directory is a symlink")
    directory = args.artifact_dir.resolve()
    if not directory.is_dir():
        raise BuildError("artifact directory is missing or a symlink")
    result = verify_artifact(directory, args.arch, run, args, tree)
    receipt = {"status": "verified", "repository": args.repo, "commit": args.commit,
               "run_id": run["id"], "run_attempt": run["run_attempt"], "artifact": result,
               "github_run_json_sha256": sha256(regular_bytes(args.run_json)),
               "github_tree_json_sha256": sha256(regular_bytes(args.tree_json)),
               "metadata_source": "supplied GitHub API responses; run status not refreshed",
               "local_compilation": False, "binaries_executed": False, "installed": False}
    write_json(args.receipt, receipt)
    print("verified API download: " + str(args.receipt))
    return 0


def download_run(args, gh, run_id):
    run = gh.run(run_id)
    validate_run(run, args)
    selected = ARCHES if args.arch == "both" else (args.arch,)
    artifacts = gh.api("actions/runs/%s/artifacts?per_page=100" % run_id)
    if artifacts.get("total_count", 0) > 100:
        raise BuildError("too many run artifacts for a complete one-page listing")
    expected = {artifact_name(arch, args.commit, run["run_attempt"]) for arch in selected}
    found = [a for a in artifacts["artifacts"] if a["name"] in expected]
    if len(found) != len(expected) or any(a.get("expired") for a in found) or {a["name"] for a in found} != expected:
        raise BuildError("required current-attempt artifacts are missing, duplicate or expired")
    git_tree = gh.api("git/trees/" + args.commit + "?recursive=1")
    if git_tree.get("truncated"):
        raise BuildError("Git tree listing is incomplete")
    tree = {item["path"]: item["sha"] for item in git_tree["tree"] if item["type"] == "blob"}
    parent = ROOT / ".build" / "github-actions"
    parent.mkdir(parents=True, exist_ok=True)
    output = parent / str(run_id)
    output.mkdir(mode=0o700)  # Existing downloads, including failed ones, are immutable.
    receipt = {"status": "downloading", "repository": args.repo, "commit": args.commit,
               "run_id": run_id, "run_attempt": run["run_attempt"], "url": run["html_url"],
               "started_at": now(), "artifacts": []}
    write_json(output / "github-run.json", run)
    try:
        for arch in selected:
            directory = output / ("linux-" + arch)
            directory.mkdir()
            command([gh.gh, "run", "download", str(run_id), "--repo", args.repo,
                     "--name", artifact_name(arch, args.commit, run["run_attempt"]), "--dir", str(directory)])
            receipt["artifacts"].append(verify_artifact(directory, arch, run, args, tree))
        latest = gh.run(run_id)
        validate_run(latest, args)
        if latest["run_attempt"] != run["run_attempt"]:
            raise BuildError("run was re-executed while downloading")
        receipt.update({"status": "verified", "finished_at": now(), "local_compilation": False,
                        "binaries_executed": False, "installed": False})
        write_json(output / "verification.json", receipt)
    except BaseException as error:
        receipt.update({"status": "failed", "finished_at": now(), "error": str(error)})
        write_json(output / "verification.json", receipt)
        raise
    print("verified download: " + str(output / "verification.json"))
    return 0


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    ci = subs.add_parser("package", help="CI-only: bind completed build to its GitHub run and package it")
    ci.add_argument("--build-dir", required=True, type=pathlib.Path)
    for name in ("list", "build-wait", "download", "verify"):
        sub = subs.add_parser(name)
        sub.add_argument("--repo", required=True, help="explicit GitHub owner/repository")
        sub.add_argument("--commit", required=True, help="exact lowercase 40-character commit SHA")
        sub.add_argument("--gh", default="gh", help="GitHub CLI executable or absolute path")
        if name == "list":
            sub.add_argument("--limit", type=int, default=10)
        elif name == "verify":
            sub.add_argument("--arch", choices=ARCHES, required=True)
            sub.add_argument("--artifact-dir", type=pathlib.Path, required=True)
            sub.add_argument("--run-json", type=pathlib.Path, required=True)
            sub.add_argument("--tree-json", type=pathlib.Path, required=True)
            sub.add_argument("--receipt", type=pathlib.Path, required=True, help="new exclusive verification record")
        else:
            sub.add_argument("--arch", choices=("both",) + ARCHES, default="both")
        if name == "download":
            sub.add_argument("--run-id", type=int, required=True)
        if name == "build-wait":
            sub.add_argument("--ref", required=True, help="already-pushed branch name")
            sub.add_argument("--timeout", type=int, default=3600, help="total wait seconds")
            sub.add_argument("--poll", type=int, default=30, help="status poll seconds (10-60)")
    args = parser.parse_args(argv)
    if args.action != "package":
        if not REPOSITORY.fullmatch(args.repo) or not SHA.fullmatch(args.commit):
            parser.error("--repo must be owner/repository and --commit must be an exact lowercase SHA")
        if args.action == "list" and not 1 <= args.limit <= 100:
            parser.error("--limit must be 1-100")
        if args.action == "download" and args.run_id <= 0:
            parser.error("--run-id must be positive")
        if args.action == "build-wait":
            if not 10 <= args.poll <= 60 or args.timeout < args.poll:
                parser.error("--poll must be 10-60 and --timeout must be at least --poll")
            if not args.ref or args.ref.startswith("-") or "\n" in args.ref:
                parser.error("invalid --ref")
    return args


def main():
    try:
        args = arguments()
        if args.action == "package":
            package(args)
            return 0
        if args.action == "verify":
            return verify_supplied(args)
        gh = GitHub(args)
        if args.action == "list":
            list_runs(args, gh)
            return 0
        if args.action == "build-wait":
            return build_wait(args, gh)
        return download_run(args, gh, args.run_id)
    except (BuildError, OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print("remote build failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
