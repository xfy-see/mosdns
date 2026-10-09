"""Download integrity checks with synthetic ELF fixtures; never invoke Go."""

import contextlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("go_remote_build", ROOT / "scripts/go-remote-build.py")
REMOTE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REMOTE)


class RemoteBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.commit = "a" * 40
        self.args = types.SimpleNamespace(repo="example/mosdns", commit=self.commit)
        self.run = {
            "id": 123, "run_attempt": 1, "head_sha": self.commit,
            "repository": {"full_name": self.args.repo}, "path": REMOTE.WORKFLOW,
            "status": "completed", "conclusion": "success",
        }

    def fixture(self, change=None, extra_member=None):
        directory = self.root / "artifact"
        directory.mkdir()
        source = b"package main\nfunc main() {}\n"
        inputs = {"main.go": {"bytes": len(source), "sha256": REMOTE.sha256(source)}}
        pipeline_data = {name: (ROOT / name).read_bytes() for name in REMOTE.PIPELINE_INPUTS}
        pipeline = {
            name: {"bytes": len(data), "sha256": REMOTE.sha256(data), "git_blob_sha1": REMOTE.blob_sha1(data)}
            for name, data in pipeline_data.items()
        }
        tree = {"main.go": REMOTE.blob_sha1(source)}
        tree.update({name: REMOTE.blob_sha1(data) for name, data in pipeline_data.items()})
        manifest = {
            "status": "complete", "requested_profile": "both", "pprof_full_only": False,
            "compression": "none", "source_and_snapshot_unchanged": True,
            "target": {"goos": "linux", "goarch": "arm64", "cgo_enabled": False},
            "toolchain": {"version": "go version go1.26.0 linux/amd64"},
            "version": "git-" + self.commit, "source_inputs": inputs,
            "source_input_tree_sha256": REMOTE.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()),
            "remote_build": {
                "repository": self.args.repo, "commit": self.commit, "run_id": 123, "run_attempt": 1,
                "workflow_file": REMOTE.WORKFLOW, "pipeline_inputs": pipeline,
                "required_tests": ["full", "minimal", "full-pprof", "race-full", "race-minimal"],
                "artifact_name": REMOTE.artifact_name("arm64", self.commit, 1),
            },
            "commands": [], "artifacts": [], "production_dependencies": {},
        }
        members = {"snapshot/main.go": source}
        members.update({"pipeline-inputs/" + name: data for name, data in pipeline_data.items()})
        elf = bytearray(120)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = (183).to_bytes(2, "little")
        elf[32:40] = (64).to_bytes(8, "little")
        elf[54:56] = (56).to_bytes(2, "little")
        elf[56:58] = (1).to_bytes(2, "little")
        elf[64:68] = (1).to_bytes(4, "little")
        for profile in ("full", "minimal"):
            name = "mosdns-" + profile + "-linux-arm64"
            data = bytes(elf)
            (directory / name).write_bytes(data)
            members[name] = data
            tags = ["mosdns_minimal"] if profile == "minimal" else []
            manifest["artifacts"].append({"profile": profile, "file": name, "tags": tags,
                                          "bytes": len(data), "sha256": REMOTE.sha256(data)})
            argv = ["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-pgo=off", "-p=2",
                    "-ldflags=-s -w -buildid= -X main.version=git-" + self.commit]
            if tags:
                argv.append("-tags=mosdns_minimal")
            argv += ["-o", "/runner/output/" + name, "."]
            manifest["commands"].append({"command": argv, "exit_code": 0,
                                          "environment": {"GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0",
                                                          "GOARM64": "v8.0", "GOAMD64": "v1"}})
            deps = b'[{"import_path":"main"}]\n'
            deps_name = profile + "-deps.json"
            members[deps_name] = deps
            manifest["production_dependencies"][profile] = {"file": deps_name, "sha256": REMOTE.sha256(deps)}
        if change:
            change(manifest)
        (directory / "manifest.json").write_text(json.dumps(manifest))
        members["manifest.json"] = (directory / "manifest.json").read_bytes()
        if extra_member:
            members[extra_member] = b"unsafe"
        with tarfile.open(directory / "mosdns-go-linux-arm64.tar.gz", "w:gz") as bundle:
            for name, data in members.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                bundle.addfile(entry, io.BytesIO(data))
        (directory / "SHA256SUMS").write_text("".join(
            REMOTE.sha256(path.read_bytes()) + "  " + path.name + "\n"
            for path in sorted(directory.iterdir()) if path.name != "SHA256SUMS"))
        return directory, tree

    def verify(self, directory, tree):
        return REMOTE.verify_artifact(directory, "arm64", self.run, self.args, tree)

    def test_complete_fixture_and_api_verify(self):
        directory, tree = self.fixture()
        self.assertEqual(self.verify(directory, tree)["source_input_count"], 1)
        run_json, tree_json = self.root / "run.json", self.root / "tree.json"
        run_json.write_text(json.dumps(self.run))
        tree_json.write_text(json.dumps({"truncated": False, "tree": [
            {"path": name, "sha": value, "type": "blob"} for name, value in tree.items()]}))
        args = types.SimpleNamespace(**vars(self.args), artifact_dir=directory, arch="arm64",
                                     run_json=run_json, tree_json=tree_json, receipt=self.root / "receipt.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(REMOTE.verify_supplied(args), 0)
        self.assertEqual(json.loads(args.receipt.read_text())["status"], "verified")
        with self.assertRaises(FileExistsError), contextlib.redirect_stdout(io.StringIO()):
            REMOTE.verify_supplied(args)

    def test_sha_tampering_rejected(self):
        directory, tree = self.fixture()
        (directory / "mosdns-minimal-linux-arm64").write_bytes(b"changed ELF")
        with self.assertRaisesRegex(REMOTE.BuildError, "checksum mismatch"):
            self.verify(directory, tree)

    def test_commit_tampering_rejected(self):
        directory, tree = self.fixture(lambda m: m["remote_build"].update(commit="b" * 40))
        with self.assertRaisesRegex(REMOTE.BuildError, "provenance mismatch"):
            self.verify(directory, tree)

    def test_source_git_blob_tampering_rejected(self):
        directory, tree = self.fixture()
        tree["main.go"] = "b" * 40
        with self.assertRaisesRegex(REMOTE.BuildError, "differs from selected Git commit"):
            self.verify(directory, tree)

    def test_archive_path_tampering_rejected(self):
        directory, tree = self.fixture(extra_member="../escape")
        with self.assertRaisesRegex(REMOTE.BuildError, "unsafe archive/input path"):
            self.verify(directory, tree)

    def test_production_flags_tampering_rejected(self):
        directory, tree = self.fixture(lambda m: m["commands"][0]["command"].remove("-trimpath"))
        with self.assertRaisesRegex(REMOTE.BuildError, "build flags differ"):
            self.verify(directory, tree)

    def test_unsuccessful_or_different_commit_run_rejected(self):
        for run in (dict(self.run, conclusion="failure"), dict(self.run, head_sha="b" * 40)):
            with self.subTest(run=run), self.assertRaises(REMOTE.BuildError):
                REMOTE.validate_run(run, self.args)

    def test_artifact_root_symlink_rejected_before_resolution(self):
        directory, _ = self.fixture()
        link = self.root / "link"
        link.symlink_to(directory, target_is_directory=True)
        run_json, tree_json = self.root / "run.json", self.root / "tree.json"
        run_json.write_text(json.dumps(self.run))
        tree_json.write_text(json.dumps({"truncated": False, "tree": []}))
        args = types.SimpleNamespace(**vars(self.args), artifact_dir=link, arch="arm64", run_json=run_json,
                                     tree_json=tree_json, receipt=self.root / "receipt.json")
        with self.assertRaisesRegex(REMOTE.BuildError, "artifact directory is a symlink"):
            REMOTE.verify_supplied(args)


if __name__ == "__main__":
    unittest.main()
