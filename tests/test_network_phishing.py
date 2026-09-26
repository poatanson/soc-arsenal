import struct
import tempfile
import unittest
from pathlib import Path

from helpers import SAMPLES, run_json, run_py


def pcap_to_pcapng(src: Path, dst: Path) -> None:
    """테스트용: 클래식 pcap → pcapng(SHB+IDB+EPB) 변환."""
    data = src.read_bytes()
    linktype = struct.unpack("<I", data[20:24])[0]
    out = bytearray()
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out += struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    out += struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    off = 24
    while off + 16 <= len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        ts = sec * 1_000_000 + usec
        padded = pkt + b"\0" * ((4 - len(pkt) % 4) % 4)
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, incl, orig) + padded
        out += struct.pack("<II", 6, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    dst.write_bytes(bytes(out))


class TestEmlAnalyzer(unittest.TestCase):
    def test_phishing_flags(self):
        proc = run_py("network_phishing/eml_analyzer.py", str(SAMPLES / "phishing.eml"), "--json")
        self.assertEqual(proc.returncode, 2)
        import json
        report = json.loads(proc.stdout)
        rules = {f["rule"] for f in report["flags"]}
        for expected in ("display-name-spoof", "reply-to-mismatch", "spf-fail", "dmarc-fail",
                         "link-text-mismatch", "dangerous-attachment", "double-extension"):
            self.assertIn(expected, rules)
        self.assertEqual(report["origin_ip"], "45.133.1.20")
        self.assertEqual(report["attachments"][0]["filename"], "Invoice_2026.pdf.exe")
        self.assertEqual(report["authentication"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})

    def test_extract_attachments_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            run_py("network_phishing/eml_analyzer.py", str(SAMPLES / "phishing.eml"), "-x", d)
            files = list(Path(d).iterdir())
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].name.endswith(".quarantine"))


class TestPcapSummary(unittest.TestCase):
    def check(self, path: Path):
        proc = run_py("network_phishing/pcap_summary.py", str(path), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        import json
        r = json.loads(proc.stdout)
        self.assertEqual(r["Overview"][0]["packets"], 31)
        self.assertEqual({q["query"] for q in r["DNS Queries"]},
                         {"www.example.com", "cdn-telemetry.top", "update-check.xyz", "github.com"})
        self.assertEqual(r["HTTP Requests"][0]["host"], "update-check.xyz")
        self.assertEqual({s["sni"] for s in r["TLS SNI"]}, {"cdn-telemetry.top", "github.com"})
        self.assertEqual([c["port"] for c in r["Non-standard Ports"]], [4444])

    def test_pcap(self):
        self.check(SAMPLES / "sample.pcap")

    def test_pcapng(self):
        with tempfile.TemporaryDirectory() as d:
            ng = Path(d) / "sample.pcapng"
            pcap_to_pcapng(SAMPLES / "sample.pcap", ng)
            self.check(ng)

    def test_not_a_pcap(self):
        proc = run_py("network_phishing/pcap_summary.py", str(SAMPLES / "auth.log"))
        self.assertEqual(proc.returncode, 1)


class TestTyposquat(unittest.TestCase):
    def test_generate(self):
        code, rows = run_json("network_phishing/typosquat_gen.py", "paypal.com")
        domains = {r["domain"]: r["technique"] for r in rows}
        self.assertEqual(domains.get("paypa1.com"), "homoglyph")
        self.assertIn("paypal.net", domains)
        self.assertIn("paypl.com", domains)
        self.assertTrue(any(d.startswith("xn--") for d in domains))
        self.assertNotIn("paypal.com", domains)

    def test_multi_level_tld(self):
        code, rows = run_json("network_phishing/typosquat_gen.py", "naver.co.kr", "--techniques", "omission")
        self.assertIn("nver.co.kr", {r["domain"] for r in rows})

    def test_check_mode(self):
        observed = "paypa1.com\nlogin.paypal.com\npaypal-secure.xyz\nexample.org\npaypal.com\n"
        proc = run_py("network_phishing/typosquat_gen.py", "paypal.com", "--check", "-", "--json", stdin=observed)
        self.assertEqual(proc.returncode, 2)
        import json
        hits = {h["domain"] for h in json.loads(proc.stdout)}
        self.assertEqual(hits, {"paypa1.com", "paypal-secure.xyz"})


class TestDnsBeacon(unittest.TestCase):
    def test_sample(self):
        code, r = run_json("network_phishing/dns_beacon_detect.py", str(SAMPLES / "dns.log"))
        self.assertEqual(code, 2)
        self.assertEqual([(b["client"], b["domain"]) for b in r["BEACON"]], [("10.0.0.23", "cdn-telemetry.top")])
        self.assertGreaterEqual(len(r["DGA"]), 10)
        self.assertTrue(all(d["clients"] == ["10.0.0.31"] for d in r["DGA"]))
        self.assertEqual([t["domain"] for t in r["TUNNELING"]], ["exfil-dns.xyz"])

    def test_zeek_format(self):
        lines = ["#separator \\x09", "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name"]
        for i in range(15):
            lines.append(f"{1790409600 + i * 300}.0\tC{i}\t10.1.1.9\t5000\t10.0.0.1\t53\tudp\t1\tbeacon-c2.xyz\tA")
        code, r = run_json("network_phishing/dns_beacon_detect.py", stdin="\n".join(lines) + "\n")
        self.assertEqual(r["BEACON"][0]["domain"], "beacon-c2.xyz")
        self.assertEqual(r["BEACON"][0]["mean_interval_s"], 300.0)

    def test_dga_score_benign(self):
        import importlib.util
        from helpers import ROOT
        spec = importlib.util.spec_from_file_location("dbd", ROOT / "network_phishing" / "dns_beacon_detect.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for label in ("wikipedia", "stackoverflow", "microsoftonline", "googleusercontent", "kakaocorp"):
            self.assertLess(mod.dga_score(label), 0.6, label)
        self.assertGreaterEqual(mod.dga_score("x8k1v0m3qz7pd2jw9"), 0.6)


if __name__ == "__main__":
    unittest.main()
