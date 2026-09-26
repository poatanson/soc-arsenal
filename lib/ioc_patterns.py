"""IOC 정규식, 추출, defang/refang."""
import ipaddress
import re
from typing import Dict, List

# 자주 쓰이는 gTLD + 모든 2글자 ccTLD. 목록에 없는 TLD는 도메인으로 보지 않는다(오탐 감소).
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "gov", "edu", "mil", "int", "io", "co",
    "xyz", "top", "online", "site", "club", "shop", "store", "app", "dev", "cloud",
    "live", "tech", "icu", "vip", "work", "buzz", "life", "link", "click", "space",
    "website", "fun", "monster", "rest", "cyou", "sbs", "cfd", "zip", "mov", "one",
    "pro", "mobi", "name", "asia", "tel", "email", "support", "help", "loan", "win",
    "bid", "download", "stream", "racing", "party", "review", "science", "date",
    "trade", "webcam", "men", "kim", "country", "gdn", "ooo", "onion", "services",
    "digital", "network", "systems", "solutions", "center", "world", "today", "news",
}

# 파일명처럼 보이는 "도메인" 오탐 제거용 (정상 ccTLD와 겹치는 확장자 포함)
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps", "ps1", "vbs", "js", "jse", "hta", "lnk",
    "py", "sh", "pl", "rb", "php", "asp", "aspx", "jsp", "txt", "log", "csv", "json",
    "xml", "html", "htm", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
    "pdf", "rtf", "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "rar", "7z", "gz",
    "tar", "tmp", "dat", "bin", "ini", "cfg", "conf", "md", "yml", "yaml", "so", "ko",
    "cs", "cpp", "h", "go", "rs", "java", "class", "jar", "msi", "iso", "img", "db",
}

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\d.]|\.\d)")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]{1,4}(?![0-9A-Fa-f:])")
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`\\\]\[)(]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.IGNORECASE)
MD5_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
SHA1_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
SHA256_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve")

_REFANG_RULES = [
    (re.compile(r"\bhxxp", re.IGNORECASE), "http"),
    (re.compile(r"\bh\[tt\]p", re.IGNORECASE), "http"),
    (re.compile(r"\bfxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[:\]//|\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\s?\[dot\]\s?|\(dot\)|\{dot\}", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\}", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\\\."), "."),
]


def refang(text: str) -> str:
    """hxxp[://]evil[.]com → http://evil.com"""
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(text: str) -> str:
    """http://evil.com/a.php → hxxp[://]evil[.]com/a.php (IP·도메인·URL·이메일만 변환)"""
    def _dots(s: str) -> str:
        return s.replace(".", "[.]")

    def _url(m: "re.Match[str]") -> str:
        url = m.group(0)
        scheme, rest = url.split("://", 1)
        host, sep, path = rest.partition("/")
        scheme = re.sub(r"^http", "hxxp", scheme, flags=re.IGNORECASE)
        scheme = re.sub(r"^ftp", "fxp", scheme, flags=re.IGNORECASE)
        return f"{scheme}[://]{_dots(host)}{sep}{path}"

    placeholders: List[str] = []

    def _stash(value: str) -> str:
        placeholders.append(value)
        return f"\x00{len(placeholders) - 1}\x00"

    text = URL_RE.sub(lambda m: _stash(_url(m)), text)
    text = EMAIL_RE.sub(lambda m: _stash(m.group(0).replace("@", "[@]").replace(".", "[.]")), text)
    text = IPV4_RE.sub(lambda m: _stash(_dots(m.group(0))), text)
    text = DOMAIN_RE.sub(lambda m: _stash(_dots(m.group(0))) if is_valid_domain(m.group(0)) else m.group(0), text)
    return re.sub(r"\x00(\d+)\x00", lambda m: placeholders[int(m.group(1))], text)


def is_valid_domain(value: str) -> bool:
    value = value.lower().rstrip(".")
    labels = value.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if tld in FILE_EXTENSIONS:
        return False
    return tld in COMMON_TLDS or (len(tld) == 2 and tld.isalpha())


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]


def is_internal_ip(value: str) -> bool:
    """RFC1918·루프백·링크로컬·CGNAT 등 조직 내부 대역 여부 (문서용 대역은 외부로 취급)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def classify(value: str) -> str:
    """단일 값의 IOC 유형을 판별. 모르면 'unknown'."""
    v = refang(value.strip())
    for name, regex in (("sha256", SHA256_RE), ("sha1", SHA1_RE), ("md5", MD5_RE)):
        if regex.fullmatch(v):
            return name
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if URL_RE.fullmatch(v):
        return "url"
    if EMAIL_RE.fullmatch(v):
        return "email"
    if CVE_RE.fullmatch(v):
        return "cve"
    if DOMAIN_RE.fullmatch(v) and is_valid_domain(v):
        return "domain"
    return "unknown"


def extract_iocs(text: str, do_refang: bool = True, include_private: bool = True) -> Dict[str, List[str]]:
    """텍스트에서 IOC를 유형별로 추출(중복 제거, 등장 순서 유지)."""
    if do_refang:
        text = refang(text)
    found: Dict[str, Dict[str, None]] = {t: {} for t in IOC_TYPES}

    for m in URL_RE.finditer(text):
        found["url"][m.group(0).rstrip(".,;:!?'\"")] = None
    for m in EMAIL_RE.finditer(text):
        found["email"][m.group(0).lower()] = None
    for m in IPV4_RE.finditer(text):
        ip = m.group(0)
        if include_private or is_public_ip(ip):
            found["ipv4"][ip] = None
    for m in IPV6_RE.finditer(text):
        try:
            ip = str(ipaddress.IPv6Address(m.group(0)))
        except ValueError:
            continue
        if include_private or is_public_ip(ip):
            found["ipv6"][ip] = None
    for m in DOMAIN_RE.finditer(text):
        dom = m.group(1).lower().rstrip(".")
        if is_valid_domain(dom):
            found["domain"][dom] = None
    for name, regex in (("sha256", SHA256_RE), ("sha1", SHA1_RE), ("md5", MD5_RE)):
        for m in regex.finditer(text):
            found[name][m.group(0).lower()] = None
    for m in CVE_RE.finditer(text):
        found["cve"][m.group(0).upper()] = None

    return {t: list(v) for t, v in found.items()}
