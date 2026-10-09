#!/usr/bin/env python3
"""Build frozen, uncompressed Go mosdns profiles without installing them."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone

SOURCE_DIRECTORIES = ("coremain", "mlog", "pkg", "plugin", "tools")
TEST_DIRECTORIES = ("tests/fixtures", "tests/profiles")
EXCLUDED_DIRECTORIES = {
    ".git", ".build", "deployments", "optimization", "__pycache__", ".pytest_cache"
}
# Proxy/auth/account environment variables deliberately never enter the manifest.
ENVIRONMENT_WHITELIST = (
    "GOOS", "GOARCH", "GOARM", "GOARM64", "GOAMD64", "GOMIPS", "GOMIPS64",
    "GORISCV64", "GOWASM", "CGO_ENABLED", "GOTOOLCHAIN", "GOENV", "GOFLAGS",
    "GOWORK", "GOROOT", "GOPATH", "GOMODCACHE", "GOCACHE", "GOMAXPROCS",
    "GOGC", "GOMEMLIMIT", "GOEXPERIMENT", "GODEBUG",
)


class BuildError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    if path.is_symlink() or not path.is_file():
        raise BuildError("source input is not a regular file: " + str(path))
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": digest(data)}


def walk_files(root):
    """Enumerate without following symlinks or accepting special file inputs."""
    if root.is_symlink() or not root.is_dir():
        raise BuildError("input directory is not a regular directory: " + str(root))
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in EXCLUDED_DIRECTORIES)
        for name in directories:
            path = pathlib.Path(directory) / name
            if path.is_symlink():
                raise BuildError("symlink directory in inputs: " + str(path))
        for name in sorted(filenames):
            if name == ".DS_Store":
                continue
            path = pathlib.Path(directory) / name
            if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
                raise BuildError("non-regular input: " + str(path))
            yield path


def source_inputs(root):
    paths = list(root.glob("*.go"))
    for name in ("go.mod", "go.sum"):
        path = root / name
        if not path.is_file():
            raise BuildError("required input missing: " + str(path))
        paths.append(path)
    for name in SOURCE_DIRECTORIES:
        paths.extend(walk_files(root / name))
    for name in TEST_DIRECTORIES:
        path = root / name
        if path.exists() or path.is_symlink():
            paths.extend(walk_files(path))
    if not any(path.name == "main.go" for path in paths):
        raise BuildError("main.go is missing")
    return {
        path.relative_to(root).as_posix(): file_record(path)
        for path in sorted(set(paths))
    }


def snapshot_inputs(root):
    # Verify the entire frozen directory, including unexpected additions.
    result = {}
    for directory, directories, filenames in os.walk(root, followlinks=False):
        for name in directories:
            if (pathlib.Path(directory) / name).is_symlink():
                raise BuildError("symlink introduced into snapshot")
        for name in filenames:
            path = pathlib.Path(directory) / name
            result[path.relative_to(root).as_posix()] = file_record(path)
    return result


def describe_difference(actual, expected):
    added = sorted(set(actual) - set(expected))
    removed = sorted(set(expected) - set(actual))
    changed = sorted(k for k in set(actual) & set(expected) if actual[k] != expected[k])
    return "added=%s removed=%s changed=%s" % (added[:10], removed[:10], changed[:10])


def validate_inputs(root, snapshot, expected):
    original = source_inputs(root)
    if original != expected:
        raise BuildError("original inputs changed: " + describe_difference(original, expected))
    frozen = snapshot_inputs(snapshot)
    if frozen != expected:
        raise BuildError("frozen inputs changed: " + describe_difference(frozen, expected))


def freeze_inputs(root, snapshot, expected):
    snapshot.mkdir(mode=0o700)
    for name, record in expected.items():
        source = root / name
        data = source.read_bytes()
        if {"bytes": len(data), "sha256": digest(data)} != record:
            raise BuildError("input changed while freezing: " + name)
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o444)
    validate_inputs(root, snapshot, expected)


def write_manifest(output, manifest):
    target = output / "manifest.json"
    temporary = output / "manifest.json.tmp"
    with temporary.open("w") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.replace(target)


def redact_tool_output(text):
    # Go errors may include a proxy URL. Do not persist URL credentials.
    return re.sub(r"(https?://)[^/\s@]+@", r"\1<redacted>@", text)


def command_record(command, cwd, env, log_name, output):
    started = utc_now()
    result = subprocess.run(
        command, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
    )
    safe_output = redact_tool_output(result.stdout)
    if result.stderr:
        safe_output += "\n[stderr]\n" + redact_tool_output(result.stderr)
    (output / log_name).write_text(safe_output)
    record = {
        "command": command, "cwd": str(cwd), "started_at": started,
        "finished_at": utc_now(), "exit_code": result.returncode,
        "log": log_name,
        "environment": {k: env[k] for k in ENVIRONMENT_WHITELIST if k in env},
    }
    return result, record


def parse_json_stream(text):
    decoder = json.JSONDecoder()
    position = 0
    values = []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        value, position = decoder.raw_decode(text, position)
        values.append(value)
    return values


def module_record(module):
    if not module:
        return None
    result = {
        k: module[k] for k in ("Path", "Version", "Sum", "GoModSum", "GoVersion", "Main")
        if k in module
    }
    if module.get("Replace"):
        result["Replace"] = module_record(module["Replace"])
    return result


def dependency_graph(text):
    packages = parse_json_stream(text)
    if not packages:
        raise BuildError("go list returned an empty production dependency graph")
    graph = []
    for package in packages:
        if package.get("Error") or package.get("DepsErrors"):
            raise BuildError("go list reported incomplete dependencies: " + package.get("ImportPath", "?"))
        module = package.get("Module", {})
        if module.get("Replace") and not module["Replace"].get("Version"):
            raise BuildError("local module replacements are outside this frozen build contract")
        graph.append({
            "import_path": package["ImportPath"],
            "standard": package.get("Standard", False),
            "imports": sorted(package.get("Imports", [])),
            "go_files": sorted(package.get("GoFiles", [])),
            "assembly_files": sorted(package.get("SFiles", [])),
            "embed_files": sorted(package.get("EmbedFiles", [])),
            "module": module_record(package.get("Module")),
        })
    return sorted(graph, key=lambda p: p["import_path"])


def go_executable(value):
    found = shutil.which(value)
    if found is None:
        raise BuildError("Go executable not found; pass --go pointing to Go 1.26")
    return pathlib.Path(found).resolve()


def build_environment(args):
    env = os.environ.copy()
    # Preserve configured caches and module-fetch settings. Disable ambient
    # workspace, persisted GOENV, toolchain downloads, and injected GOFLAGS.
    env.update({
        "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "",
        "CGO_ENABLED": "0", "GOOS": args.goos, "GOARCH": args.goarch,
    })
    return env


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go 1.26 executable or path")
    parser.add_argument("--output", type=pathlib.Path, help="new exclusive output directory")
    parser.add_argument("--profile", choices=("full", "minimal", "both"), default="both")
    parser.add_argument("--goos", default="linux")
    parser.add_argument("--goarch", default="arm64")
    parser.add_argument("--version", default="dev/unknown", help="embedded version (letters, digits, . _ / + ~ -)")
    parser.add_argument("--pprof", action="store_true", help="enable pprof in the full profile only")
    args = parser.parse_args(argv)
    if args.profile == "minimal" and args.pprof:
        parser.error("--pprof is unavailable for --profile minimal; use the full profile")
    if not re.fullmatch(r"[A-Za-z0-9._/+~-]{1,128}", args.version):
        parser.error("--version must be 1-128 letters, digits or . _ / + ~ -")
    for name in ("goos", "goarch"):
        if not re.fullmatch(r"[a-z0-9]+", getattr(args, name)):
            parser.error("--" + name + " must be a Go target name")
    return args


def run_build(args, root):
    root = root.resolve()
    output = args.output or root / ".build" / (
        "go-profiles-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
    )
    output = output.resolve()
    # A new build directory inside captured source could recursively freeze its
    # own snapshot. Such destinations cannot be valid immutable build inputs.
    for name in SOURCE_DIRECTORIES + TEST_DIRECTORIES:
        source_directory = root / name
        if output == source_directory or source_directory in output.parents:
            raise BuildError("output must be outside source input directories")
    if output == root:
        raise BuildError("output cannot be the repository root")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)  # Exclusive: an existing directory is always an error.
    manifest = {
        "format_version": 1, "status": "building", "started_at": utc_now(),
        "repository": str(root), "output": str(output),
        "target": {"goos": args.goos, "goarch": args.goarch, "cgo_enabled": False},
        "requested_profile": args.profile, "version": args.version,
        "pprof_full_only": args.pprof, "compression": "none", "installed": False,
        "commands": [], "artifacts": [], "production_dependencies": {},
    }
    write_manifest(output, manifest)
    try:
        go = go_executable(args.go)
        env = build_environment(args)
        result, record = command_record([str(go), "version"], root, env, "go-version.log", output)
        manifest["commands"].append(record)
        if result.returncode or not re.match(r"^go version go1\.26(?:\.\d+)?\s", result.stdout):
            raise BuildError("a stable Go 1.26 toolchain is required; see go-version.log")
        manifest["toolchain"] = {
            "executable": str(go), "version": result.stdout.strip(),
            "executable_sha256": file_record(go)["sha256"],
        }
        inputs = source_inputs(root)
        manifest["source_inputs"] = inputs
        manifest["source_input_tree_sha256"] = digest(
            json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
        )
        snapshot = output / "snapshot"
        freeze_inputs(root, snapshot, inputs)
        manifest["snapshot"] = "snapshot"
        profiles = ("full", "minimal") if args.profile == "both" else (args.profile,)
        artifacts = []
        for profile in profiles:
            tags = ["mosdns_minimal"] if profile == "minimal" else (["pprof"] if args.pprof else [])
            tag_options = ["-tags=" + ",".join(tags)] if tags else []
            validate_inputs(root, snapshot, inputs)
            command = [str(go), "list", "-mod=readonly", "-deps", "-json"] + tag_options + ["."]
            result, record = command_record(command, snapshot, env, profile + "-deps.log", output)
            manifest["commands"].append(record)
            validate_inputs(root, snapshot, inputs)
            if result.returncode:
                raise BuildError(profile + " dependency resolution failed; see " + profile + "-deps.log")
            graph = dependency_graph(result.stdout)
            deps_file = profile + "-deps.json"
            (output / deps_file).write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n")
            manifest["production_dependencies"][profile] = {
                "file": deps_file, "package_count": len(graph),
                "sha256": file_record(output / deps_file)["sha256"],
                "kind": "production only; go list without -test", "tags": tags,
            }
            name = "mosdns-" + profile + "-" + args.goos + "-" + args.goarch
            if args.goos == "windows":
                name += ".exe"
            target = output / name
            validate_inputs(root, snapshot, inputs)
            command = [
                str(go), "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-pgo=off", "-p=2",
                "-ldflags=-s -w -buildid= -X main.version=" + args.version,
            ] + tag_options + ["-o", str(target), "."]
            result, record = command_record(command, snapshot, env, profile + "-build.log", output)
            manifest["commands"].append(record)
            validate_inputs(root, snapshot, inputs)
            if result.returncode:
                raise BuildError(profile + " build failed; see " + profile + "-build.log")
            artifacts.append({"profile": profile, "file": name, "tags": tags, **file_record(target)})
            write_manifest(output, manifest)
        validate_inputs(root, snapshot, inputs)
        if file_record(go)["sha256"] != manifest["toolchain"]["executable_sha256"]:
            raise BuildError("Go executable changed during the build")
        for artifact in artifacts:
            if file_record(output / artifact["file"]) != {k: artifact[k] for k in ("bytes", "sha256")}:
                raise BuildError("artifact changed before final validation")
        manifest.update({
            "artifacts": artifacts, "status": "complete", "finished_at": utc_now(),
            "source_and_snapshot_unchanged": True,
        })
        write_manifest(output, manifest)
        return output
    except BaseException as error:
        manifest.update({
            "status": "failed", "finished_at": utc_now(),
            "error": redact_tool_output(str(error) or type(error).__name__),
        })
        write_manifest(output, manifest)
        raise


def main():
    args = parse_arguments()
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        output = run_build(args, root)
    except (BuildError, OSError, ValueError) as error:
        print("build failed: " + redact_tool_output(str(error)), file=sys.stderr)
        return 1
    print("build complete: " + str(output / "manifest.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
