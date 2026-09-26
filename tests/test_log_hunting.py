import unittest

from helpers import SAMPLES, run_json, run_py


class TestSshBruteforce(unittest.TestCase):
    def test_detects_bruteforce_and_compromise(self):
        code, rows = run_json("log_hunting/ssh_bruteforce.py", str(SAMPLES / "auth.log"))
        self.assertEqual(code, 2)
        by_ip = {r["ip"]: r for r in rows}
        attacker = by_ip["203.0.113.50"]
        self.assertIn("COMPROMISE_SUSPECTED", attacker["flags"])
        self.assertIn("BRUTEFORCE", attacker["flags"])
        self.assertEqual(attacker["failures"], 12)
        self.assertEqual(attacker["success_users"], ["admin"])
        self.assertEqual(by_ip["198.51.100.23"]["flags"], ["PASSWORD_SPRAY"])
        # 정상 내부 사용자는 탐지되지 않는다
        self.assertNotIn("10.0.0.15", by_ip)

    def test_threshold_option(self):
        code, rows = run_json("log_hunting/ssh_bruteforce.py", str(SAMPLES / "auth.log"),
                              "--threshold", "100", "--spray-users", "100")
        self.assertEqual(code, 0)
        self.assertEqual(rows, [])

    def test_stdin(self):
        line = "Sep 26 03:20:01 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
        proc = run_py("log_hunting/ssh_bruteforce.py", "-t", "3", "--json", stdin=line * 3)
        self.assertEqual(proc.returncode, 2)


class TestWebAttackHunter(unittest.TestCase):
    def test_categories(self):
        code, rows = run_json("log_hunting/web_attack_hunter.py", str(SAMPLES / "access.log"))
        self.assertEqual(code, 2)
        cats = {c for r in rows for c in r["categories"]}
        for expected in ("sqli", "xss", "lfi", "rce", "log4shell", "webshell", "recon", "scanner"):
            self.assertIn(expected, cats)
        # 정상 트래픽(10.0.0.x)은 탐지되지 않는다
        self.assertFalse([r for r in rows if r["ip"].startswith("10.")])

    def test_summary_and_filter(self):
        code, rows = run_json("log_hunting/web_attack_hunter.py", str(SAMPLES / "access.log"),
                              "--summary", "--category", "sqli")
        self.assertEqual([r["ip"] for r in rows], ["192.0.2.77"])

    def test_benign_words_not_flagged(self):
        benign = '1.1.1.1 - - [26/Sep/2026:08:00:01 +0900] "GET /blog/sleep-tips-for-union-workers HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n'
        proc = run_py("log_hunting/web_attack_hunter.py", "--json", stdin=benign)
        self.assertEqual(proc.returncode, 0, proc.stdout)


class TestEvtxHunter(unittest.TestCase):
    def test_rules(self):
        code, rows = run_json("log_hunting/evtx_hunter.py", str(SAMPLES / "security_events.xml"))
        self.assertEqual(code, 2)
        rules = {r["rule"] for r in rows}
        for expected in ("bruteforce+password-spray", "logon-after-failures", "cmd:encoded-powershell",
                         "cmd:certutil-download", "user-created", "group-member-added",
                         "service-installed", "scheduled-task-created", "log-cleared"):
            self.assertIn(expected, rules)
        # 정상 WINWORD 실행은 탐지되지 않는다
        self.assertFalse([r for r in rows if "WINWORD" in r["detail"]])

    def test_min_severity(self):
        code, rows = run_json("log_hunting/evtx_hunter.py", str(SAMPLES / "security_events.xml"),
                              "--min-severity", "critical")
        self.assertEqual({r["rule"] for r in rows}, {"logon-after-failures"})

    def test_rootless_wevtutil_output(self):
        # wevtutil 을 /e 없이 뽑으면 루트 요소가 없다
        import tempfile
        from pathlib import Path
        xml = (SAMPLES / "security_events.xml").read_text(encoding="utf-8")
        body = xml.split("<Events>", 1)[1].rsplit("</Events>", 1)[0]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rootless.xml"
            p.write_text(body, encoding="utf-8")
            code, rows = run_json("log_hunting/evtx_hunter.py", str(p))
        self.assertEqual(code, 2)
        self.assertTrue(any(r["rule"] == "log-cleared" for r in rows))


if __name__ == "__main__":
    unittest.main()
