#!/usr/bin/env python3
"""Build the exact test bundle on a remote CI runner; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASELINE = "9cfb7ce985599c087cb7ccfb1531d0c0f4021242"


def run(argv, log, **kwargs):
    with log.open("ab") as stream:
        subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=True, **kwargs)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    p.add_argument("--commit", required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if commit != a.commit or len(commit) != 40:
        p.error("checkout must equal the requested full commit SHA")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        p.error("build only on GitHub Actions; local work downloads remote products")
    if subprocess.check_output(["go", "env", "GOVERSION"], text=True).strip() != "go1.26.0":
        p.error("Go 1.26.0 is required")
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    log = output / "build.log"
    env = dict(os.environ, GOOS="linux", GOARCH=a.arch, CGO_ENABLED="0")
    manifest = {"schema_version": 1, "source_commit": commit, "goarch": a.arch,
                "baseline_commit": BASELINE, "files": {}, "status": "failed"}
    baseline = output / "baseline-source"
    try:
        run([sys.executable, str(root / "benchmarks/build-go-profiles.py"), "--go", shutil.which("go"),
             "--goos", "linux", "--goarch", a.arch, "--profile", "both", "--version", "git-" + commit,
             "--output", str(output / "profiles")], log, cwd=root, env=env)
        for profile in ("full", "minimal"):
            shutil.copyfile(output / "profiles" / ("mosdns-" + profile + "-linux-" + a.arch),
                            output / ("mosdns-" + profile))
        run(["git", "worktree", "add", "--detach", str(baseline), BASELINE], log, cwd=root)
        flags = ["-mod=readonly", "-trimpath", "-buildvcs=false", "-pgo=off", "-p=2"]
        run(["go", "build", *flags, "-ldflags=-s -w -buildid= -X main.version=git-" + BASELINE,
             "-o", str(output / "mosdns-baseline"), "."], log, cwd=baseline, env=env)
        for helper, package in (("dnsbench", "./benchmarks/dnsbench"),
                                ("routerproxy", "./benchmarks/routerproxy")):
            run(["go", "build", *flags, "-ldflags=-s -w -buildid=", "-o", str(output / helper), package],
                log, cwd=root, env=env)
        for name in ("mosdns-baseline", "mosdns-full", "mosdns-minimal", "dnsbench", "routerproxy"):
            path = output / name
            path.chmod(0o755)
            data = path.read_bytes()
            manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                        "source_commit": BASELINE if name == "mosdns-baseline" else commit}
        manifest["status"] = "passed"
    finally:
        if baseline.exists():
            try:
                run(["git", "worktree", "remove", "--force", str(baseline)], log, cwd=root)
            except subprocess.SubprocessError:
                manifest["status"] = "failed"
                manifest["cleanup_error"] = "baseline worktree cleanup failed; see build.log"
        (output / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (output / "results.json").write_text(json.dumps({"schema_version": 1, "suite": "build-" + a.arch,
            "source_commit": commit, "status": manifest["status"], "environment": {"goarch": a.arch},
            "checks": [{"name": "frozen test bundle", "status": manifest["status"], "detail": "See bundle.json and build.log"}],
            "measurements": [], "limitations": [], "artifacts": ["bundle.json", "build.log"]}, indent=2) + "\n")
    if manifest["status"] != "passed":
        raise RuntimeError("bundle build or cleanup failed")


if __name__ == "__main__":
    main()
