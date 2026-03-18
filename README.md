<div align="center">

```

 ██▓███   ▄▄▄     ▄▄▄█████▓ ██░ ██  ██▓███   ██▓     █    ██  ███▄    █ ▓█████▄ ▓█████  ██▀███  ▓█████  ██▀███  
▓██░  ██▒▒████▄   ▓  ██▒ ▓▒▓██░ ██▒▓██░  ██▒▓██▒     ██  ▓██▒ ██ ▀█   █ ▒██▀ ██▌▓█   ▀ ▓██ ▒ ██▒▓█   ▀ ▓██ ▒ ██▒
▓██░ ██▓▒▒██  ▀█▄ ▒ ▓██░ ▒░▒██▀▀██░▓██░ ██▓▒▒██░    ▓██  ▒██░▓██  ▀█ ██▒░██   █▌▒███   ▓██ ░▄█ ▒▒███   ▓██ ░▄█ ▒
▒██▄█▓▒ ▒░██▄▄▄▄██░ ▓██▓ ░ ░▓█ ░██ ▒██▄█▓▒ ▒▒██░    ▓▓█  ░██░▓██▒  ▐▌██▒░▓█▄   ▌▒▓█  ▄ ▒██▀▀█▄  ▒▓█  ▄ ▒██▀▀█▄  
▒██▒ ░  ░ ▓█   ▓██▒ ▒██▒ ░ ░▓█▒░██▓▒██▒ ░  ░░██████▒▒▒█████▓ ▒██░   ▓██░░▒████▓ ░▒████▒░██▓ ▒██▒░▒████▒░██▓ ▒██▒
▒▓▒░ ░  ░ ▒▒   ▓▒█░ ▒ ░░    ▒ ░░▒░▒▒▓▒░ ░  ░░ ▒░▓  ░░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒  ▒▒▓  ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒▓ ░▒▓░
░▒ ░       ▒   ▒▒ ░   ░     ▒ ░▒░ ░░▒ ░     ░ ░ ▒  ░░░▒░ ░ ░ ░ ░░   ░ ▒░ ░ ▒  ▒  ░ ░  ░  ░▒ ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
░░         ░   ▒    ░       ░  ░░ ░░░         ░ ░    ░░░ ░ ░    ░   ░ ░  ░ ░  ░    ░     ░░   ░    ░     ░░   ░ 
               ░  ░         ░  ░  ░             ░  ░   ░              ░    ░       ░  ░   ░        ░  ░   ░     
                                                                         ░                                              
```

**🔍 Web Recon & Attack Surface Discovery**

`dir` · `subdomain` · `vhost` · `fuzz` · `cloud` · `xmlrpc`

[![Python](https://img.shields.io/badge/python-3.8%2B-00BFFF?style=plastic&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/version-4.2-FF1493?style=plastic&logo=github&logoColor=white)](https://github.com/VictorAzariah/PathPlunderer/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-00C853?style=plastic&logo=linux&logoColor=white)]()

*Inspired by [gobuster](https://github.com/OJ/gobuster) · [feroxbuster](https://github.com/epi052/feroxbuster) · [cloud_enum](https://github.com/initstring/cloud_enum) · [lazys3](https://github.com/nahamsec/lazys3) · [SecLists](https://github.com/danielmiessler/SecLists)*

</div>

---

> 💡 *"If something is truly perfect, then that's it — there is nothing left. There is no room for imagination. No place left for that person to gain additional knowledge or improvement. That's the kind of creatures we are. We take joy in trying to exceed our grasp and trying to reach for something that, in the end, we have to admit, may in fact be unreachable!"*
>
> ~ **Kurotsuchi Mayuri** *(Bleach)*

---

## 🧰 Overview

PathPlunderer is a Python web recon tool built for offensive security work. It combines directory brute-forcing, 403 bypass, parameter mining, subdomain enumeration, virtual host discovery, parameter fuzzing, multi-cloud bucket enumeration, and WordPress XML-RPC brute-force — all in one unified CLI with clean, aligned output.

```bash
python pathplunderer.py -m dir -u https://target.com -x php --probe --secrets --bypass-403 --wayback --wayback-filter-status 200,301
```

<p align="center">
  <img src="demo.gif" alt="PathPlunderer Demo" width="750"/>
</p>

---

## ⚡ Install & Update

```bash
git clone https://github.com/VictorAzariah/PathPlunderer
cd PathPlunderer
pip install -r requirements.txt
```

> **Dependencies:** `colorama` · `requests` · `tqdm` · `dnspython`

> **Keep it updated:** Run `python pathplunderer.py --update` at any time to automatically pull the latest version directly from GitHub.

---

## 🗺️ Modes

```
python pathplunderer.py -m <mode> [options]
python pathplunderer.py -m <mode> --help
```

| Mode | 💡 What it does |
|------|----------------|
| 🗂️ `dir` | Directory & file brute-force — 403 Bypass, Param Mining, Crawl, Wayback, secrets, WP detection |
| 🌐 `subdomain` | DNS subdomain enumeration |
| 🖥️ `vhost` | Virtual host discovery via `Host:` header manipulation |
| 🎯 `fuzz` | URL / body / header fuzzer — replaces `FUZZ` keyword anywhere |
| ☁️ `cloud` | Multi-cloud bucket enum — AWS S3 · GCP Storage · Azure Blob |
| 🔑 `xmlrpc` | WordPress XML-RPC credential brute-force via `xmlrpc.php` |

---

## 🧠 What Sets PathPlunderer Apart

Most directory scanners either recurse into **everything** (flooding requests into `/images/`, `/css/`, `/fonts/`) or skip recursion entirely. PathPlunderer does neither.

### 🔁 Smart Recursion *(default — no flag needed)*

Recurses automatically into directories that could contain sensitive content, and silently skips the noise:

| ⛔ Skipped (static assets) | ✅ Recursed into |
|---------------------------|----------------|
| `/images/` `/img/` `/css/` `/fonts/` | `/api/` `/admin/` `/js/` |
| `/icons/` `/sprites/` `/thumbnails/` | `/v1/` `/v2/` `/uploads/` |
| `/videos/` `/audio/` `/gfx/` | `/config/` `/backup/` `/docs/` |

```bash
# 🧠 Smart recurse — default, no flag needed
python pathplunderer.py -m dir -u https://target.com -w wordlists/big.txt

# 🔓 Full recurse — go into every discovered directory
python pathplunderer.py -m dir -u https://target.com -w wordlists/big.txt --recurse

# 🚫 Flat scan — no recursion at all
python pathplunderer.py -m dir -u https://target.com -w wordlists/big.txt --no-recurse
```

### 🕰️ Wayback Machine CDX API

PathPlunderer doesn't just scan what is currently on the server; it looks at what *used* to be there. By querying the Wayback Machine CDX API, it surfaces forgotten endpoints, exposed secrets in old files, and historical paths that might still be active but are no longer linked.

* **Live Checking:** Automatically verifies if the archived URLs are still accessible on the live target.
* **Smart Filtering:** Use `--wayback-filter-status` to easily cut through the noise and only return active or forbidden pages (e.g., 200, 301, 403).
* **Passive Recon:** Use `--wayback-all` to instantly dump every known historical URL without sending a single aggressive request to the target server.

### 📂 Directory Listing Detection & Enumeration

Automatically detects open `Index of /` listings and alerts you immediately. By default, it won't flood your terminal with files. However, you can use `--list-dir` to force PathPlunderer to parse the listing and automatically `HEAD`-check every exposed file:

```bash
python pathplunderer.py -m dir -u [https://target.com](https://target.com) --list-dir
```

### 🕷️ Post-Scan Crawl *(always on)*

After the wordlist scan, PathPlunderer visits discovered pages and extracts links from HTML. Any new URLs not already found by the wordlist are shown with a `[CRAWL]` tag — 301s, 403s, 500s included. 404s are silently dropped.

---

## 🗂️ Dir Mode

### Output Format

Feroxbuster-style fixed-width columns — status, method, lines, words, bytes, URL:

```
  200  GET     65l     877w    5266c  https://target.com/login.php
  301  GET      2l      28w     169c  https://target.com/admin  → https://target.com/admin/
  403  GET      0l       0w       0c  https://target.com/secret  [CRAWL]
```

### ⚙️ Scan Phases

| \# | Phase | Triggered by |
|---|-------|-------------|
| 1 | 🔧 Server calibration — latency, timeout, wildcard detection | always |
| 2 | 📋 **Dir scan** — wordlist × extensions, smart-recursive | always |
| 3 | 🕷️ **Crawl** — visit found pages, surface missed URLs | always |
| 4 | 🔭 **Probe** — 130+ known sensitive paths | `--probe` |
| 5 | ⛏️ **Param Mine** — discover hidden GET/POST parameters | `--param-mine` |
| 6 | 🔓 **403 Bypass** — 100+ bypass techniques | `--bypass-403` |
| 7 | 🔑 **Secrets** — deep-crawl responses for leaked credentials | `--secrets` |
| 8 | 🕰️ **Wayback** — query Wayback Machine CDX API | `--wayback` |

### 📌 Examples

```bash
# Default — smart recurse on, crawl on, auto-loads wordlists/common.txt
python pathplunderer.py -m dir -u https://target.com

# With extensions + full recon suite
python pathplunderer.py -m dir -u https://target.com -w wordlists/directory-list-2.3-medium.txt -x php,zip --probe --secrets --bypass-403 --wayback --param-mine

# Bypass-only mode (skip wordlist scan)
python pathplunderer.py -m dir -u https://target.com/admin --bypass-only

# Wayback dump only
python pathplunderer.py -m dir -u https://target.com --wayback-only --wayback-all --wayback-filter-status 200,301

# Parameter Mining
python pathplunderer.py -m dir -u [https://target.com](https://target.com) --param-mine

# WordPress theme + plugin version detection
python pathplunderer.py -m dir -u https://wpsite.com -x php --wp-detect

# High-speed scan
python pathplunderer.py -m dir -u https://target.com -w wordlists/raft-large-words.txt -t 100
```

### ⛏️ Parameter Mining (`--param-mine`)

Using techniques popularized by PortSwigger's Param Miner, PathPlunderer automatically injects batches of parameters with cache-busters to discover hidden endpoints and custom headers on all discovered pages.

  * Evaluates GET queries, POST form-data, JSON bodies, and `X-*` headers.
  * Analyzes response length and body hashes to rule out false positives.
  * Detects parameter reflection to identify potential XSS vulnerabilities on the fly.

### 🔓 403 Bypass Techniques

PathPlunderer runs **100+ bypass techniques** on every 403 response:

- 🛤️ **Path variants** — `/admin/./` · `/admin//` · `/%2fadmin` · `/admin%00`
- 🔤 **Encoding** — double-encode · Unicode normalization · null bytes
- 📨 **Headers** — `X-Forwarded-For` · `X-Original-URL` · `X-Rewrite-URL` · `X-Real-IP` · `X-Custom-IP-Authorization` · 20+ more
- 🪟 **IIS** — `/admin;param=value` · **Tomcat** path params · **Spring Boot** Actuator tricks
- 🌐 **CDN** — Akamai and Cloudflare specific bypass headers

### 🔑 Secrets Detection

40+ patterns — including: AWS access keys · GCP service account JSON · private keys (RSA/EC/PGP) · JWTs · Stripe / Shopify / Twilio / SendGrid API keys · Slack webhooks · GitHub / GitLab tokens · Telegram bot tokens · database connection strings · `.env` variable dumps

**v4.2 Update:** The secrets module now performs a secondary deep-crawl on found endpoints specifically looking for linked JavaScript or configuration files that contain hardcoded tokens.

### 🌐 WordPress Detection `--wp-detect`

While crawling, PathPlunderer parses HTML source and extracts WordPress theme and plugin names along with version numbers from `?ver=` query parameters:

```
  [WP-THEME]   twentytwentytwo                          ver:1.3
  [WP-PLUGIN]  contact-form-7                           ver:5.7.6
  [WP-PLUGIN]  woocommerce                              ver:8.2.1
```

---

## 🌐 Subdomain Mode

```bash
python pathplunderer.py -m subdomain --domain target.com -w wordlists/subdomains-top5000.txt --resolver 8.8.8.8 --check-cname -t 200 -o subs.txt
```

---

## 🖥️ VHost Mode

```bash
# HTB / CTF style
python pathplunderer.py -m vhost -u http://10.10.11.100 -w wordlists/vhosts.txt --domain target.htb --append-domain

# Filter noise by response size
python pathplunderer.py -m vhost -u https://10.10.10.5 -w wordlists/subdomains-top5000.txt --domain target.htb --xs 4242
```

---

## 🎯 Fuzz Mode

The `FUZZ` keyword can go anywhere — URL path, POST body, or headers.

```bash
# Path fuzzing
python pathplunderer.py -m fuzz -u "https://api.target.com/v1/user/FUZZ" -w wordlists/api-endpoints.txt

# POST credential brute-force (URL-encoded body, like ffuf -d)
python pathplunderer.py -m fuzz -u "https://target.com/login" --data-urlencoded "user=admin&password=FUZZ" -w wordlists/rockyou.txt -b 200

# JSON body fuzzing (Content-Type: application/json set automatically)
python pathplunderer.py -m fuzz -u "https://api.target.com/auth" --data-json '{"user":"admin","pass":"FUZZ"}' -w wordlists/passwords.txt -b 401

# Header fuzzing
python pathplunderer.py -m fuzz -u "https://target.com" -H "X-Api-Version: FUZZ" -w wordlists/fuzz-general.txt
```

---

## ☁️ Cloud Mode

Generates keyword mutations and probes all three major cloud providers — methodology from **cloud_enum** and **lazys3**.

```bash
# Single keyword
python pathplunderer.py -m cloud -k acmecorp

# Multiple keywords + custom mutation list
python pathplunderer.py -m cloud -k acme -k acme-corp -M wordlists/cloud_mutations.txt -t 20

# Exact keywords only, no mutation expansion
python pathplunderer.py -m cloud -k acmecorp --quickscan

# Disable specific providers
python pathplunderer.py -m cloud -k target --disable-azure
```

| ☁️ Provider | 🔢 Endpoints |
|------------|-------------|
| AWS S3 | 22 — virtual-hosted + path-style + all major regions + `-local` variant |
| GCP Storage | 7 — googleapis.com, Firebase Storage, App Engine |
| Azure | 10 + DNS CNAME fingerprinting |

| 🚦 Status | Meaning |
|----------|---------|
| 🟢 **OPEN** | Bucket exists and lists files publicly |
| 🔒 **PRIVATE** | Bucket exists, authentication required |
| 🔵 **DNS-EXISTS** | CNAME resolves — bucket exists even if HTTP is locked |

---

## 🔑 XML-RPC Mode

Brute-forces WordPress credentials via `xmlrpc.php` using the `wp.getUsersBlogs` XML-RPC method.

```bash
# Single username + password list
python pathplunderer.py -m xmlrpc -u https://target.com -U admin -P wordlists/rockyou.txt -t 20

# Username list + password list, stop on first hit
python pathplunderer.py -m xmlrpc -u https://target.com -U wordlists/users.txt -P wordlists/passwords.txt --stop-on-first

# Through Burp Suite
python pathplunderer.py -m xmlrpc -u https://target.com -U admin -P passwords.txt --burp -t 5
```

---

## 📂 Wordlists

All wordlists are included in the `wordlists/` folder. `wordlists/common.txt` is **auto-loaded** when `-w` is not specified.

| 📄 File | 🎯 Best for |
|---------|------------|
| `common.txt` | Fast default scan (~200 high-value paths) |
| `directory-list-2.3-medium.txt` | DirBuster classic — thorough dir scan |
| `raft-large-words.txt` | Best overall dir/fuzz coverage |
| `big.txt` | Wide dir scan |
| `subdomains-top5000.txt` | Quick subdomain enum |
| `subdomains-top20000.txt` | Deep subdomain enum |
| `vhosts.txt` | VHost brute-force |
| `api-endpoints.txt` | API path fuzzing |
| `fuzz-general.txt` | General fuzzing payloads |
| `cloud_mutations.txt` | Cloud bucket mutations (177 entries) |

---

## ⚠️ Legal

For **authorized security testing only**. Ensure you have explicit written permission before scanning any system. The author is not responsible for misuse.

---

<div align="center">
<i>PathPlunderer v4.2 · by Victor Azariah</i><br/>
<i>Inspired by gobuster · feroxbuster · cloud_enum · lazys3 · SecLists</i>
</div>
