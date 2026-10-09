import contextlib
import importlib.util
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


RELEASE_SCRIPT = Path(__file__).resolve().parents[1] / "release.py"


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old_cwd = Path.cwd()
        self.addCleanup(os.chdir, self.old_cwd)
        os.chdir(self.temp.name)
        Path("README.md").write_text("readme\n")
        Path("LICENSE").write_text("license\n")
        self.calls = []

    def load(self, arguments=()):
        spec = importlib.util.spec_from_file_location("release_under_test", RELEASE_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, "argv", [str(RELEASE_SCRIPT), *arguments]):
            spec.loader.exec_module(module)
        return module

    def fake_call(self, command, **kwargs):
        self.assertIsInstance(command, list)
        self.assertNotIn("shell", kwargs)
        self.calls.append((command, kwargs))
        if command[:2] == ["go", "run"]:
            Path("config.yaml").write_text("plugins: []\n")
        elif command[:2] == ["go", "build"]:
            Path(command[command.index("-o") + 1]).write_bytes(b"test executable")
        return 0

    @contextlib.contextmanager
    def fake_tools(self, module, call=None, version=b"v5.3.3-0-g123abc\n"):
        with mock.patch.object(module.subprocess, "check_output", return_value=version) as git:
            with mock.patch.object(module.subprocess, "check_call", side_effect=call or self.fake_call):
                yield git

    def build_calls(self):
        return [(command, opts) for command, opts in self.calls if command[:2] == ["go", "build"]]

    def test_index_zero_selects_only_first_platform(self):
        module = self.load(["-i", "0"])
        with self.fake_tools(module) as git:
            self.assertEqual(module.main(), 0)
        git.assert_called_once_with(["git", "describe", "--tags", "--long", "--always"])
        builds = self.build_calls()
        self.assertEqual(len(builds), 1)
        command, opts = builds[0]
        self.assertEqual((opts["env"]["GOOS"], opts["env"]["GOARCH"]), ("darwin", "amd64"))
        self.assertEqual(command[command.index("-ldflags") + 1], "-s -w -X main.version=v5.3.3-0-g123abc")
        with zipfile.ZipFile("mosdns-darwin-amd64.zip") as archive:
            self.assertEqual(set(archive.namelist()), {"mosdns", "README.md", "LICENSE", "config.yaml"})
            self.assertEqual(archive.read("config.yaml"), b"plugins: []\n")

    def test_default_builds_all_platforms_without_mutating_environment(self):
        module = self.load()
        before = dict(os.environ)
        platforms = [[pair[:] for pair in platform] for platform in module.envs]
        with self.fake_tools(module):
            self.assertEqual(module.main(), 0)
        self.assertEqual(len(self.build_calls()), len(platforms))
        for (_, opts), platform in zip(self.build_calls(), platforms):
            for key, value in platform:
                self.assertEqual(opts["env"][key], value)
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(module.envs, platforms)
        self.assertTrue(Path("mosdns-windows-amd64.zip").exists())
        with zipfile.ZipFile("mosdns-windows-amd64.zip") as archive:
            self.assertIn("mosdns.exe", archive.namelist())

    def test_failed_target_does_not_report_release_success(self):
        module = self.load()

        def fail_first_build(command, **kwargs):
            if command[:2] == ["go", "build"] and kwargs["env"]["GOOS"] == "darwin" and kwargs["env"]["GOARCH"] == "amd64":
                self.calls.append((command, kwargs))
                raise subprocess.CalledProcessError(1, command)
            return self.fake_call(command, **kwargs)

        with self.fake_tools(module, call=fail_first_build), self.assertLogs(module.logger, "ERROR"):
            self.assertEqual(module.main(), 1)
        self.assertEqual(len(self.build_calls()), len(module.envs))
        self.assertFalse(Path("mosdns-darwin-amd64.zip").exists())
        self.assertTrue(Path("mosdns-darwin-arm64.zip").exists())

    def test_script_exits_nonzero_when_single_platform_build_fails(self):
        def fail_build(command, **kwargs):
            if command[:2] == ["go", "build"]:
                raise subprocess.CalledProcessError(3, command)
            return self.fake_call(command, **kwargs)

        with mock.patch.object(sys, "argv", [str(RELEASE_SCRIPT), "-i", "0"]):
            with mock.patch.object(subprocess, "check_output", return_value=b"v-test\n"):
                with mock.patch.object(subprocess, "check_call", side_effect=fail_build):
                    with self.assertRaises(SystemExit) as raised:
                        with contextlib.redirect_stderr(io.StringIO()):
                            runpy.run_path(str(RELEASE_SCRIPT), run_name="__main__")
        self.assertEqual(raised.exception.code, 1)

    def test_invalid_platform_index_is_rejected_before_build(self):
        total = len(self.load().envs)
        for value in ("-1", str(total)):
            with self.subTest(index=value), mock.patch.object(subprocess, "check_call") as call:
                with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()):
                    self.load(["-i", value])
                self.assertEqual(raised.exception.code, 2)
                call.assert_not_called()
        self.assertFalse(Path("release").exists())

    def test_failed_template_generation_stops_before_build(self):
        module = self.load(["-i", "0"])

        def fail_template(command, **kwargs):
            self.calls.append((command, kwargs))
            raise subprocess.CalledProcessError(2, command)

        with self.fake_tools(module, call=fail_template), self.assertLogs(module.logger, "ERROR"):
            with self.assertRaises(subprocess.CalledProcessError):
                module.main()
        self.assertEqual(self.build_calls(), [])
        self.assertEqual(list(Path.cwd().glob("*.zip")), [])

    def test_failed_git_description_preserves_unknown_version_fallback(self):
        module = self.load(["-i", "0"])
        with mock.patch.object(module.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, ["git"])):
            with mock.patch.object(module.subprocess, "check_call", side_effect=self.fake_call), self.assertLogs(module.logger, "ERROR"):
                self.assertEqual(module.main(), 0)
        command, _ = self.build_calls()[0]
        self.assertEqual(command[command.index("-ldflags") + 1], "-s -w -X main.version=dev/unknown")

    def test_packaging_failure_is_not_hidden(self):
        module = self.load(["-i", "0"])
        with self.fake_tools(module), mock.patch.object(module.zipfile, "ZipFile", side_effect=OSError("cannot create archive")):
            with self.assertLogs(module.logger, "ERROR"):
                self.assertEqual(module.main(), 1)

    def test_missing_git_preserves_unknown_version_fallback(self):
        module = self.load(["-i", "0"])
        with mock.patch.object(module.subprocess, "check_output", side_effect=FileNotFoundError("git")):
            with mock.patch.object(module.subprocess, "check_call", side_effect=self.fake_call), self.assertLogs(module.logger, "ERROR"):
                self.assertEqual(module.main(), 0)
        command, _ = self.build_calls()[0]
        self.assertEqual(command[command.index("-ldflags") + 1], "-s -w -X main.version=dev/unknown")

    def test_optional_upx_failure_keeps_uncompressed_release(self):
        module = self.load(["-i", "0", "-upx"])

        def fail_upx(command, **kwargs):
            if command[0] == "upx":
                self.calls.append((command, kwargs))
                raise subprocess.CalledProcessError(1, command)
            return self.fake_call(command, **kwargs)

        with self.fake_tools(module, call=fail_upx), self.assertLogs(module.logger, "ERROR"):
            self.assertEqual(module.main(), 0)
        self.assertTrue(Path("mosdns-darwin-amd64.zip").exists())

    def test_missing_optional_upx_keeps_uncompressed_release(self):
        module = self.load(["-i", "0", "-upx"])

        def missing_upx(command, **kwargs):
            if command[0] == "upx":
                raise FileNotFoundError("upx")
            return self.fake_call(command, **kwargs)

        with self.fake_tools(module, call=missing_upx), self.assertLogs(module.logger, "ERROR"):
            self.assertEqual(module.main(), 0)
        self.assertTrue(Path("mosdns-darwin-amd64.zip").exists())


if __name__ == "__main__":
    unittest.main()
