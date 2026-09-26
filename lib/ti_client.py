"""위협 인텔 API 클라이언트 (VirusTotal / AbuseIPDB / urlscan.io).

- API 키는 환경변수 또는 저장소 루트의 .env 에서만 읽는다.
- 키가 없으면 해당 제공자는 조용히 건너뛴다 (status="no_api_key").
- 결과는 ~/.cache/soc-arsenal 에 캐시한다 (기본 24시간).
"""
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = Path(os.environ.get("SOC_ARSENAL_CACHE", Path.home() / ".cache" / "soc-arsenal"))
CACHE_TTL = int(os.environ.get("SOC_ARSENAL_CACHE_TTL", 86400))
USER_AGENT = "soc-arsenal/1.0"

# 무료 티어 기준 최소 요청 간격(초)
MIN_INTERVAL = {"virustotal": 15.0, "abuseipdb": 1.0, "urlscan": 2.0}
_last_call: Dict[str, float] = {}


def load_dotenv(path: Path = REPO_ROOT / ".env") -> None:
    """간단한 .env 로더. 이미 설정된 환경변수는 덮어쓰지 않는다."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


load_dotenv()


def api_key(provider: str) -> Optional[str]:
    env = {"virustotal": "VT_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY",
           "urlscan": "URLSCAN_API_KEY"}[provider]
    return os.environ.get(env) or None


def available_providers() -> Dict[str, bool]:
    return {p: api_key(p) is not None for p in ("virustotal", "abuseipdb", "urlscan")}


def _cache_path(provider: str, key: str) -> Path:
    digest = hashlib.sha256(f"{provider}:{key}".encode()).hexdigest()
    return CACHE_DIR / provider / f"{digest}.json"


def _cache_get(provider: str, key: str) -> Optional[Dict[str, Any]]:
    path = _cache_path(provider, key)
    try:
        if time.time() - path.stat().st_mtime < CACHE_TTL:
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return None


def _cache_put(provider: str, key: str, data: Dict[str, Any]) -> None:
    path = _cache_path(provider, key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def _throttle(provider: str) -> None:
    wait = MIN_INTERVAL[provider] - (time.time() - _last_call.get(provider, 0))
    if wait > 0:
        time.sleep(wait)
    _last_call[provider] = time.time()


def _http_get(provider: str, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """GET 요청 후 {'http_status': int, 'body': dict|None, 'error': str|None} 반환."""
    _throttle(provider)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return {"http_status": resp.status, "body": json.loads(resp.read().decode()), "error": None}
    except urllib.error.HTTPError as e:
        messages = {401: "인증 실패(API 키 확인)", 403: "권한 없음", 404: "not_found",
                    429: "요청 한도 초과(rate limit)"}
        return {"http_status": e.code, "body": None, "error": messages.get(e.code, f"HTTP {e.code}")}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"http_status": 0, "body": None, "error": f"네트워크 오류: {e}"}
    except ValueError:
        return {"http_status": 0, "body": None, "error": "JSON 파싱 실패"}


def _cached_lookup(provider: str, key: str, fetch, use_cache: bool) -> Dict[str, Any]:
    if not api_key(provider):
        return {"provider": provider, "status": "no_api_key"}
    if use_cache:
        cached = _cache_get(provider, key)
        if cached is not None:
            return {**cached, "cached": True}
    result = fetch()
    # 실패(네트워크, 한도 초과 등)는 캐시하지 않는다
    if result.get("status") in ("ok", "not_found"):
        _cache_put(provider, key, result)
    return result


# ---------------------------------------------------------------- VirusTotal

def virustotal(ioc: str, ioc_type: str, use_cache: bool = True) -> Dict[str, Any]:
    """ioc_type: ipv4/ipv6/domain/url/md5/sha1/sha256"""
    if ioc_type in ("ipv4", "ipv6"):
        path, gui = f"ip_addresses/{ioc}", f"ip-address/{ioc}"
    elif ioc_type == "domain":
        path, gui = f"domains/{ioc}", f"domain/{ioc}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        path, gui = f"urls/{url_id}", f"url/{hashlib.sha256(ioc.encode()).hexdigest()}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        path, gui = f"files/{ioc}", f"file/{ioc}"
    else:
        return {"provider": "virustotal", "status": "unsupported_type"}

    def fetch() -> Dict[str, Any]:
        resp = _http_get("virustotal", f"https://www.virustotal.com/api/v3/{path}",
                         {"x-apikey": api_key("virustotal") or ""})
        base = {"provider": "virustotal", "link": f"https://www.virustotal.com/gui/{gui}"}
        if resp["error"] == "not_found":
            return {**base, "status": "not_found"}
        if resp["error"]:
            return {**base, "status": "error", "error": resp["error"]}
        attrs = resp["body"].get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            **base, "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
            "name": attrs.get("meaningful_name"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
        }

    return _cached_lookup("virustotal", f"{ioc_type}:{ioc}", fetch, use_cache)


# ---------------------------------------------------------------- AbuseIPDB

def abuseipdb(ip: str, max_age_days: int = 90, use_cache: bool = True) -> Dict[str, Any]:
    def fetch() -> Dict[str, Any]:
        qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
        resp = _http_get("abuseipdb", f"https://api.abuseipdb.com/api/v2/check?{qs}",
                         {"Key": api_key("abuseipdb") or "", "Accept": "application/json"})
        base = {"provider": "abuseipdb", "link": f"https://www.abuseipdb.com/check/{ip}"}
        if resp["error"]:
            return {**base, "status": "error", "error": resp["error"]}
        d = resp["body"].get("data", {})
        return {
            **base, "status": "ok",
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor"),
            "last_reported": d.get("lastReportedAt"),
        }

    return _cached_lookup("abuseipdb", f"{ip}:{max_age_days}", fetch, use_cache)


# ---------------------------------------------------------------- urlscan.io

def urlscan_search(ioc: str, ioc_type: str, use_cache: bool = True) -> Dict[str, Any]:
    field = {"domain": "domain", "ipv4": "ip", "ipv6": "ip", "url": "page.url",
             "sha256": "hash"}.get(ioc_type)
    if not field:
        return {"provider": "urlscan", "status": "unsupported_type"}

    def fetch() -> Dict[str, Any]:
        value = json.dumps(ioc) if ioc_type == "url" else ioc
        qs = urllib.parse.urlencode({"q": f"{field}:{value}", "size": 10})
        resp = _http_get("urlscan", f"https://urlscan.io/api/v1/search/?{qs}",
                         {"API-Key": api_key("urlscan") or ""})
        base = {"provider": "urlscan"}
        if resp["error"]:
            return {**base, "status": "error", "error": resp["error"]}
        results = resp["body"].get("results", [])
        latest = results[0] if results else {}
        return {
            **base, "status": "ok" if results else "not_found",
            "total_scans": resp["body"].get("total", len(results)),
            "latest_scan": latest.get("task", {}).get("time"),
            "link": latest.get("result"),
        }

    return _cached_lookup("urlscan", f"{ioc_type}:{ioc}", fetch, use_cache)
