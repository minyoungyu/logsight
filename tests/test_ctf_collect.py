"""CTF 팀 서버가 1분마다 올린 로그 조각을 이어 붙이면 LogFinder가 종류를 알아보고 읽는지."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

from logsight.normalize import detect_kind, parse_sshauth

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ctf_collect", ROOT / "lab" / "ctf" / "collect_logs.py")
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)

SUDO = b"Nov 26 05:41:02 ip-10-20-10-11 sudo[2211]:    nginx : PWD=/var/www/shop/uploads ; USER=root ; COMMAND=/usr/bin/find /var/www/shop/uploads -exec cat /root/flag4.txt ;\n"
WEB1 = b'10.20.0.37 - t01 [26/Nov/2026:05:30:01 +0000] "GET /robots.txt HTTP/1.1" 200 74 "-" "curl/8.5" "203.0.113.45"\n'
WEB2 = b'10.20.0.37 - t01 [26/Nov/2026:05:31:10 +0000] "POST /admin/login.php HTTP/1.1" 302 0 "-" "curl/8.5" "203.0.113.45"\n'


class CollectTest(unittest.TestCase):
    def _piece(self, root, team, name, epoch, off, data):
        d = root / "hosts" / team / name
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{epoch}-{off}.log").write_bytes(data)

    def test_chunk_name_alone_hides_sudo_only_auth_log(self):
        # 조각 이름만으로는 종류를 모르고, sshd 줄이 없는 auth.log는 내용으로도 못 알아본다(이 스크립트가 필요한 이유).
        self.assertIsNone(detect_kind("1795000000-0.log", SUDO.decode()))

    def test_assembles_in_order_with_kind_in_name(self):
        with tempfile.TemporaryDirectory() as t:
            raw, out = Path(t) / "raw", Path(t) / "out"
            self._piece(raw, "t01", "nginx-access", 1795000060, len(WEB1), WEB2)
            self._piece(raw, "t01", "nginx-access", 1795000000, 0, WEB1)
            self._piece(raw, "t01", "auth", 1795000100, 0, SUDO)
            self._piece(raw, "t01", "messages", 1795000100, 0, b"x\n")
            rep = collect.assemble_hosts(raw / "hosts", out)

            web = out / "analyze" / "hosts" / "t01-nginx-access.log"
            self.assertEqual(web.read_bytes(), WEB1 + WEB2)
            self.assertEqual(detect_kind(web.name, web.read_text()), "weblog")
            self.assertEqual(rep["t01/nginx-access"]["restarts"], [])

            auth = out / "analyze" / "hosts" / "t01-auth.log"
            self.assertEqual(detect_kind(auth.name, auth.read_text()), "sshauth")
            evs = parse_sshauth(auth.read_text(), year=2026)
            self.assertEqual([e.action for e in evs], ["sudo"])

            self.assertTrue((out / "extra" / "hosts" / "t01-messages.log").exists())
            self.assertFalse((out / "analyze" / "hosts" / "t01-messages.log").exists())

    def test_records_restart_when_file_was_truncated(self):
        with tempfile.TemporaryDirectory() as t:
            raw, out = Path(t) / "raw", Path(t) / "out"
            self._piece(raw, "t02", "auth", 1795000000, 0, SUDO)
            self._piece(raw, "t02", "auth", 1795000300, 0, SUDO)  # 참가자가 root로 auth.log를 비운 뒤
            rep = collect.assemble_hosts(raw / "hosts", out)
            self.assertEqual(len(rep["t02/auth"]["restarts"]), 1)
            self.assertEqual((out / "analyze" / "hosts" / "t02-auth.log").read_bytes(), SUDO + SUDO)

    def test_identical_secure_moved_out_of_analysis(self):
        # Amazon Linux 2023은 auth.log와 secure에 같은 줄을 남긴다: 둘 다 분석하면 sudo·계정 생성이 두 번 세진다
        with tempfile.TemporaryDirectory() as t:
            raw, out = Path(t) / "raw", Path(t) / "out"
            self._piece(raw, "t01", "auth", 1795000000, 0, SUDO)
            self._piece(raw, "t01", "secure", 1795000000, 0, SUDO)
            self._piece(raw, "t02", "auth", 1795000000, 0, SUDO)
            self._piece(raw, "t02", "secure", 1795000000, 0, SUDO + SUDO)  # 다르면 그대로 둔다
            rep = collect.assemble_hosts(raw / "hosts", out)
            self.assertFalse((out / "analyze" / "hosts" / "t01-secure.log").exists())
            self.assertTrue((out / "extra" / "hosts" / "t01-secure.log").exists())
            self.assertIn("note", rep["t01/secure"])
            self.assertTrue((out / "analyze" / "hosts" / "t02-secure.log").exists())


if __name__ == "__main__":
    unittest.main()
