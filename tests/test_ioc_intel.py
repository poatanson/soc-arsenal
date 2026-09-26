import unittest

from helpers import SAMPLES, run_json, run_py

from lib.ioc_patterns import classify, defang, extract_iocs, is_internal_ip, refang


class TestIocPatterns(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(refang("hxxps[://]evil[.]com/a"), "https://evil.com/a")
        self.assertEqual(refang("1[.]2(.)3{.}4"), "1.2.3.4")
        self.assertEqual(refang("bad(at)evil[dot]org"), "bad@evil.org")

    def test_defang_roundtrip(self):
        text = "go to http://evil.com/x.php from 8.8.8.8 or mail a@b.net"
        defanged = defang(text)
        self.assertNotIn("http://", defanged)
        self.assertIn("8[.]8[.]8[.]8", defanged)
        self.assertEqual(refang(defanged), text)

    def test_defang_leaves_filenames(self):
        self.assertEqual(defang("run loader.dll and stage2.exe"), "run loader.dll and stage2.exe")

    def test_extract_from_report(self):
        found = extract_iocs((SAMPLES / "threat_report.txt").read_text(encoding="utf-8"))
        self.assertIn("185.220.101.45", found["ipv4"])
        self.assertIn("45.133.1.20", found["ipv4"])
        self.assertIn("cdn-telemetry.top", found["domain"])
        self.assertIn("http://update-check.xyz/payload.bin", found["url"])
        self.assertEqual(found["md5"], ["44d88612fea8a8f36de82e1278abb02f"])
        self.assertEqual(len(found["sha256"]), 1)
        self.assertEqual(found["cve"], ["CVE-2024-3400", "CVE-2023-4966"])
        # 파일명은 도메인으로 오탐하지 않는다
        for fp in ("loader.dll", "stage2.exe", "invoice_2026.docm"):
            self.assertNotIn(fp, found["domain"])

    def test_extract_public_only(self):
        found = extract_iocs("10.0.0.1 192.168.1.1 8.8.8.8", include_private=False)
        self.assertEqual(found["ipv4"], ["8.8.8.8"])

    def test_classify(self):
        self.assertEqual(classify("8.8.8.8"), "ipv4")
        self.assertEqual(classify("evil[.]com"), "domain")
        self.assertEqual(classify("hxxp://evil.com/a"), "url")
        self.assertEqual(classify("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        self.assertEqual(classify("notes.txt"), "unknown")

    def test_internal_ip(self):
        self.assertTrue(is_internal_ip("10.1.2.3"))
        self.assertTrue(is_internal_ip("172.20.0.1"))
        self.assertFalse(is_internal_ip("203.0.113.50"))
        self.assertFalse(is_internal_ip("8.8.8.8"))


class TestIocScripts(unittest.TestCase):
    def test_ioc_extract_cli(self):
        code, rows = run_json("ioc_intel/ioc_extract.py", str(SAMPLES / "threat_report.txt"), "--types", "ipv4",
                              "--public-only")
        self.assertEqual(code, 0)
        self.assertEqual({r["value"] for r in rows}, {"185.220.101.45", "45.133.1.20"})

    def test_ioc_extract_plain_stdin(self):
        proc = run_py("ioc_intel/ioc_extract.py", "--plain", "--types", "domain", stdin="visit evil[.]top now")
        self.assertEqual(proc.stdout.strip(), "evil.top")

    def test_defang_cli(self):
        proc = run_py("ioc_intel/defang.py", "http://evil.com")
        self.assertEqual(proc.stdout.strip(), "hxxp[://]evil[.]com")
        proc = run_py("ioc_intel/defang.py", "-r", "hxxp[://]evil[.]com")
        self.assertEqual(proc.stdout.strip(), "http://evil.com")

    def test_enrich_offline_without_keys(self):
        code, rows = run_json("ioc_intel/ioc_enrich.py", "8.8.8.8", "10.0.0.1", "evil.com")
        self.assertEqual(code, 0)
        verdicts = {r["ioc"]: r["verdict"] for r in rows}
        self.assertEqual(verdicts, {"8.8.8.8": "not_checked", "10.0.0.1": "private", "evil.com": "not_checked"})

    def test_enrich_verdict_logic(self):
        import importlib.util
        from helpers import ROOT
        spec = importlib.util.spec_from_file_location("ioc_enrich", ROOT / "ioc_intel" / "ioc_enrich.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.verdict({"status": "ok", "malicious": 5, "suspicious": 0}, {}), "malicious")
        self.assertEqual(mod.verdict({}, {"status": "ok", "abuse_score": 80}), "malicious")
        self.assertEqual(mod.verdict({"status": "ok", "malicious": 1, "suspicious": 0}, {}), "suspicious")
        self.assertEqual(mod.verdict({"status": "ok", "malicious": 0, "suspicious": 0}, {}), "clean")
        self.assertEqual(mod.verdict({"status": "no_api_key"}, {}), "unknown")


if __name__ == "__main__":
    unittest.main()
