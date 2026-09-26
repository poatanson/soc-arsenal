import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import BASH, ROOT, SAMPLES, run_bash, run_json, run_py

STUB_SHA256 = "487502c51f69f8136a1cd1fe1259e9ff60e5c17cc9c34baacb748b17de7c22b0"


class TestFileHashScan(unittest.TestCase):
    def test_known_bad_match(self):
        code, rows = run_json("incident_response/file_hash_scan.py", str(SAMPLES / "evidence"),
                              "-k", str(SAMPLES / "known_bad_hashes.txt"))
        self.assertEqual(code, 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["matched"], STUB_SHA256)
        self.assertEqual(rows[0]["description"], "SilentFox-dropper (sample)")

    def test_baseline_diff(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "app"
            root.mkdir()
            (root / "a.txt").write_text("a")
            (root / "b.txt").write_text("b")
            manifest = run_py("incident_response/file_hash_scan.py", str(root), "--manifest")
            base = Path(d) / "base.csv"
            base.write_text(manifest.stdout, encoding="utf-8")
            (root / "a.txt").write_text("changed")
            (root / "b.txt").unlink()
            (root / "c.txt").write_text("new")
            code, rows = run_json("incident_response/file_hash_scan.py", str(root), "--baseline", str(base))
        self.assertEqual(code, 2)
        status = {Path(r["path"]).name: r["status"] for r in rows}
        self.assertEqual(status, {"a.txt": "MODIFIED", "b.txt": "DELETED", "c.txt": "ADDED"})

    def test_requires_mode(self):
        proc = run_py("incident_response/file_hash_scan.py", str(SAMPLES))
        self.assertEqual(proc.returncode, 1)


@unittest.skipUnless(BASH, "bash 가 없음")
class TestBashScripts(unittest.TestCase):
    def test_no_crlf(self):
        # CRLF 가 섞이면 Linux 에서 "$'\r': command not found" 로 실행 실패
        for script in sorted(ROOT.glob("*/*.sh")) + sorted(ROOT.glob("*/*.py")):
            self.assertNotIn(b"\r", script.read_bytes(), f"{script.relative_to(ROOT)} 에 CRLF 포함")

    def test_syntax(self):
        for script in sorted(ROOT.glob("*/*.sh")):
            proc = subprocess.run([BASH, "-n", str(script)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"{script.name}: {proc.stderr}")

    def test_log_timeline_order_and_filter(self):
        proc = run_bash("log_hunting/log_timeline.sh", "-y", "2026", "-s", "2026-09-26 08:00",
                        "-e", "2026-09-26 08:05", str(SAMPLES / "access.log"), str(SAMPLES / "dns.log"),
                        str(SAMPLES / "auth.log"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.strip().splitlines()
        stamps = [l.split("\t")[0] for l in lines]
        self.assertEqual(stamps, sorted(stamps))
        self.assertTrue(all("2026-09-26 08:00" <= s <= "2026-09-26 08:05:59" for s in stamps))
        self.assertEqual({l.split("\t")[1] for l in lines}, {"access.log", "dns.log"})

    def test_log_timeline_grep(self):
        proc = run_bash("log_hunting/log_timeline.sh", "-y", "2026", "-g", "Accepted",
                        str(SAMPLES / "auth.log"))
        self.assertEqual(len(proc.stdout.strip().splitlines()), 3)
        self.assertTrue(proc.stdout.startswith("2026-09-26 03:12:44\tauth.log\t"))

    def test_hash_lookup(self):
        proc = run_bash("ioc_intel/hash_lookup.sh", str(SAMPLES / "evidence" / "dropper_stub.bin"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        header, row = proc.stdout.strip().splitlines()
        self.assertEqual(header, "path,size,md5,sha1,sha256")
        self.assertTrue(row.endswith(STUB_SHA256))


if __name__ == "__main__":
    unittest.main()
