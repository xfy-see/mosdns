"""Controller safety/parser tests do not connect to a device or compile Go."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("router_workflow", ROOT / "scripts/testworkflow/router.py")
router = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(router)


def packet(answer=True, flags=0x8180, query_id=123):
    name = b"\x03www\x07example\x03com\0"
    message = struct.pack("!6H", query_id, flags, 1, int(answer), 0, 0) + name + struct.pack("!HH", 1, 1)
    if answer:
        message += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return message


class RouterWorkflowTests(unittest.TestCase):
    def test_dns_compressed_answer_and_question(self):
        result = router.parse_answer(packet(), 123, "www.example.com", 1)
        self.assertEqual(result["addresses"], [{"ip": "1.2.3.4", "type": "A", "ttl": 60}])
        for wrong in (packet(query_id=124), packet(flags=0x8380), packet(flags=0x8183), packet()[:-1]):
            with self.assertRaises(router.Failed):
                router.parse_answer(wrong, 123, "www.example.com", 1)

    def test_dns_pointer_cycle_and_nodata(self):
        with self.assertRaises(router.Failed):
            router.decode_name(b"\xc0\x00", 0)
        with self.assertRaises(router.Failed):
            router.parse_answer(packet(answer=False), 123, "www.example.com", 1)
        self.assertEqual(router.parse_answer(packet(answer=False), 123, "www.example.com", 1, False)["addresses"], [])

    def test_static_elf_rejects_interpreter_and_dependency(self):
        data = bytearray(128)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, 183)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        router.static_arm64(data)
        struct.pack_into("<I", data, 64, 3)
        with self.assertRaises(router.Blocked):
            router.static_arm64(data)
        struct.pack_into("<I", data, 64, 2)
        struct.pack_into("<Q", data, 72, 112)
        struct.pack_into("<Q", data, 96, 16)
        struct.pack_into("<q", data, 112, 1)
        with self.assertRaises(router.Blocked):
            router.static_arm64(data)

    def test_config_does_not_open_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            config = json.loads((ROOT / "scripts/testworkflow/router-config.example.json").read_text())
            for field in ("ssh_identity", "ssh_known_hosts", "cn_site_file", "cn_ip_file"):
                file = directory / field
                file.write_text("PRIVATE_SENTINEL")
                config[field] = str(file)
            config["ssh_host_fingerprint"] = "SHA256:" + "a" * 43
            config["wireguard_interface"] = "wgtest"
            file = directory / "private.json"
            file.write_text(json.dumps(config))
            original = Path.read_bytes
            opened = []
            def read(path):
                opened.append(path)
                self.assertNotEqual(path, directory / "ssh_identity")
                return original(path)
            with patch.object(Path, "read_bytes", read):
                router.load_config(file)
            self.assertEqual(opened, [file])
            config["listener_port"] = config["mock_port"]
            file.write_text(json.dumps(config))
            with self.assertRaises(router.Blocked):
                router.load_config(file)

    def test_nft_normalization_keeps_static_set_content(self):
        first = {"set": {"table": "fw4", "name": "cn", "type": "ipv4_addr", "elem": ["1.2.3.4"]}}
        changed = {"set": {"table": "fw4", "name": "cn", "type": "ipv4_addr", "elem": ["5.6.7.8"]}}
        self.assertNotEqual(router.nft_view(first), router.nft_view(changed))
        first["set"]["flags"] = ["timeout"]
        changed["set"]["flags"] = ["timeout"]
        self.assertEqual(router.nft_view(first), router.nft_view(changed))
        changed["set"]["timeout"] = 10000
        self.assertNotEqual(router.nft_view(first), router.nft_view(changed))

    def test_cleanup_shell_uses_owned_lock_and_group(self):
        config = dict(cgroup_parent="/sys/fs/cgroup/test", ssh_port=22, ssh_identity="/private/key",
                      ssh_known_hosts="/private/pin", host="192.168.100.131")
        with tempfile.TemporaryDirectory() as directory:
            instance = router.Controller(config, {}, {}, directory, "a" * 40)
            instance.boot = "12345678-1234-1234-1234-123456789abc"
            script = instance.cleanup_script()
            subprocess.run(["sh", "-n"], input=script, text=True, check=True)
            self.assertIn('lock_owned || exit 1', script)
            self.assertIn('[ ! -e "$R" ] || rmdir "$R"', script)
            self.assertNotIn('rm -rf', script)
            self.assertNotIn('/sys/fs/cgroup/cgroup.subtree_control', script)

    def test_insufficient_flash_blocks_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            config = json.loads((ROOT / "scripts/testworkflow/router-config.example.json").read_text())
            config["wireguard_interface"] = "wgtest"
            for field, content in (("cn_site_file", "domain:cn-site.test\n"), ("cn_ip_file", "1.2.3.4/32\n")):
                file = directory / field
                file.write_text(content)
                config[field] = str(file)
            instance = router.Controller(config, {}, {"mosdns-full": b"ELF"}, directory, "a" * 40)
            instance.boot = "12345678-1234-1234-1234-123456789abc"
            instance.direct_dns = "192.168.100.1"
            commands = []
            instance.remote = lambda script, *args: commands.append(script) or b"0\n"
            with self.assertRaises(router.Blocked):
                instance.deploy()
            self.assertFalse(instance.deployed)
            self.assertEqual(len(commands), 1)
            self.assertIn("df -Pk /root", commands[0])
            self.assertNotIn("mkdir", commands[0])

    def test_failed_upload_invokes_scoped_cleanup(self):
        config = dict(cgroup_parent="/sys/fs/cgroup/test", ssh_port=22, ssh_identity="/private/key",
                      ssh_known_hosts="/private/pin", host="192.168.100.131")
        with tempfile.TemporaryDirectory() as directory:
            instance = router.Controller(config, {}, {}, directory, "a" * 40)
            instance.boot = "12345678-1234-1234-1234-123456789abc"
            called = []
            def deploy():
                instance.deployed = True
                raise router.Failed("payload upload failed")
            instance.preflight = lambda: None
            instance.deploy = deploy
            instance.cleanup = lambda: called.append("cleanup")
            instance.execute(True)
            self.assertEqual(called, ["cleanup"])
            self.assertEqual(instance.result["status"], "failed")
            self.assertTrue((Path(directory) / "results.json").is_file())


if __name__ == "__main__":
    unittest.main()
