"""테스트 공통 헬퍼: 스크립트를 서브프로세스로 실행."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
sys.path.insert(0, str(ROOT))

BASH = shutil.which("bash")
_CACHE = tempfile.mkdtemp(prefix="soc-arsenal-test-cache-")


def clean_env() -> dict:
    env = dict(os.environ)
    for key in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY"):
        env[key] = ""  # .env 로더가 덮어쓰지 않도록 빈 값으로 고정
    env["PYTHONUTF8"] = "1"
    env["SOC_ARSENAL_CACHE"] = _CACHE
    return env


def run_py(script: str, *args: str, stdin: str = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / script), *args], input=stdin, capture_output=True,
                          text=True, encoding="utf-8", env=clean_env(), cwd=ROOT, timeout=120)


def run_json(script: str, *args: str, stdin: str = None):
    proc = run_py(script, *args, "--json", stdin=stdin)
    assert proc.stdout.strip(), proc.stderr
    return proc.returncode, json.loads(proc.stdout)


def run_bash(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, str(ROOT / script), *args], capture_output=True, text=True,
                          encoding="utf-8", env=clean_env(), cwd=ROOT, timeout=120)
