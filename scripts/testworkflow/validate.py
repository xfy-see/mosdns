#!/usr/bin/env python3
"""Run profile regressions and retain their terminal status and JSON events."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", choices=("full", "minimal", "full-pprof"), required=True)
    p.add_argument("--race", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--commit", required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    suite = ("race-" if a.race else "unit-") + a.profile
    checks = []
    status = "failed"
    try:
        current = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        if current != a.commit:
            raise ValueError("checkout differs from requested commit")
        command = ["go", "test", "-mod=readonly", "-p=2", "-parallel=2", "-count=1", "-json"]
        if a.profile == "minimal":
            command += ["-tags=mosdns_minimal"]
        elif a.profile == "full-pprof":
            command += ["-tags=pprof"]
        command += (["-race", "./pkg/matcher/domain", "./pkg/query_context", "./pkg/cache",
                     "./pkg/concurrent_map", "./plugin/executable/cache"] if a.race else ["./..."])
        with (a.output / "go-test.jsonl").open("wb") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1200)
        checks.append({"name": "Go test exit status", "status": "passed" if result.returncode == 0 else "failed",
                       "detail": "exit=" + str(result.returncode)})
        if not a.race and a.profile == "full":
            with (a.output / "python-test.log").open("wb") as log:
                result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
                                        stdout=log, stderr=subprocess.STDOUT, timeout=120)
            checks.append({"name": "Python controller regressions", "status": "passed" if result.returncode == 0 else "failed",
                           "detail": "exit=" + str(result.returncode)})
        status = "passed" if all(c["status"] == "passed" for c in checks) else "failed"
    except Exception as e:
        checks.append({"name": "test execution", "status": "failed", "detail": str(e)})
    finally:
        (a.output / "results.json").write_text(json.dumps({"schema_version": 1, "suite": suite,
            "source_commit": a.commit, "status": status, "checks": checks, "measurements": [],
            "environment": {"profile": a.profile, "race": a.race}, "limitations": [],
            "artifacts": [x.name for x in a.output.iterdir() if x.is_file()]}, indent=2) + "\n")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
