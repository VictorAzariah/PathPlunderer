<div align="center">

```text
        ____        __  __    ____  __               __                     
       / __ \____ _/ /_/ /_  / __ \/ /_  ______  ___/ /___  ________  _____ 
      / /_/ / __ `/ __/ __ \/ /_/ / / / / / __ \/ __  / _ \/ ___/ _ \/ ___/ 
     / ____/ /_/ / /_/ / / / ____/ / /_/ / / / / /_/ /  __/ /  /  __/ /     
    /_/    \__,_/\__/_/ /_/_/   /_/\__,_/_/ /_/\__,_/\___/_/   \___/_/      

```

### ⚡ Web Recon & Attack Surface Discovery ⚡

🗂️ `dir` · 🌍 `subdomain` · 🖥️ `vhost` · 🎯 `fuzz` · ☁️ `cloud` · 🔓 `xmlrpc`

*Inspired by [gobuster](https://github.com/OJ/gobuster) · [feroxbuster](https://github.com/epi052/feroxbuster) · [cloud_enum](https://github.com/initstring/cloud_enum) · [lazys3](https://github.com/nahamsec/lazys3) · [SecLists*](https://github.com/danielmiessler/SecLists)

> 💡 *"If something is truly perfect, then that's it — there is nothing left. There is no room for imagination. No place left for that person to gain additional knowledge or improvement. That's the kind of creatures we are. We take joy in trying to exceed our grasp and trying to reach for something that, in the end, we have to admit, may in fact be unreachable!"*
> 
> 
> 
> 
> — **Kurotsuchi Mayuri (Bleach)**

</div>

---

## 🔎 Overview

**PathPlunderer** is a Python web recon tool built for offensive security work. It combines directory brute-forcing, 403 bypass, subdomain enumeration, virtual host discovery, parameter fuzzing, multi-cloud bucket enumeration, and WordPress XML-RPC brute-force in one unified CLI. Every mode shares the same clean, aligned output format.

```bash
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com) \
  -x php --probe --secrets --bypass-403 \
  --wayback --wayback-filter-status 200,301

```

<p align="center">
<img src="demo.gif" alt="PathPlunderer Demo" width="800" style="border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.2);"/>
</p>

---

## ⚙️ Install

Get up and running in seconds.

```bash
git clone [https://github.com/VictorAzariah/PathPlunderer](https://github.com/VictorAzariah/PathPlunderer)
cd PathPlunderer
pip install -r requirements.txt

```

> **Dependencies:** `colorama` · `requests` · `tqdm` · `dnspython`

---

## 🚀 Usage

Execute a module using the <kbd>-m</kbd> flag, followed by your target and options.

```bash
python3 pathplunderer.py -m <mode> [options]
python3 pathplunderer.py -m <mode> --help

```

### 🛠️ Available Modes

| Mode | Description |
| --- | --- |
| 📂 **`dir`** | Directory & file brute-force with smart recurse, 403 bypass, crawl, Wayback, secrets, WP detection |
| 🌍 **`subdomain`** | DNS subdomain enumeration |
| 🖥️ **`vhost`** | Virtual host discovery via `Host:` header |
| 🎯 **`fuzz`** | URL / body / header fuzzer — replaces `FUZZ` keyword |
| ☁️ **`cloud`** | Multi-cloud bucket enum — AWS S3 · GCP Storage · Azure Blob |
| 🔓 **`xmlrpc`** | WordPress XML-RPC brute-force via `xmlrpc.php` |

---

## 🧠 What Sets PathPlunderer Apart

Most directory brute-force tools either recurse into everything (slowing the scan with hundreds of requests to `/images/`, `/css/`, `/fonts/`) or disable recursion entirely. **PathPlunderer does neither.**

### 🎯 Smart Recursion (default)

PathPlunderer recurses automatically — but *only* into directories that could actually contain sensitive content. Static asset directories are skipped by default:

| ⏭️ Skipped automatically | 🔍 Recursed into |
| --- | --- |
| `/images/`, `/img/`, `/css/`, `/fonts/` | `/api/`, `/admin/`, `/js/` |
| `/icons/`, `/sprites/`, `/thumbnails/` | `/v1/`, `/v2/`, `/uploads/` |
| `/videos/`, `/audio/`, `/gfx/` | `/config/`, `/backup/`, `/docs/` |

```bash
# Smart recurse (default) — automatic, no flag needed
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com) -w wordlists/big.txt

# Full recurse — go into every directory including static ones
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com) -w wordlists/big.txt --recurse

# Flat scan — no recursion at all
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com) -w wordlists/big.txt --no-recurse

```

### 📂 Directory Listing Detection

PathPlunderer automatically detects open directory listings during the scan (`Index of /` patterns) and alerts you immediately — without printing every file inside the directory:

```text
[DIR-LIST] Open directory listing: [https://target.com/uploads/](https://target.com/uploads/)

```

### 🕸️ Post-Scan Crawl

After the wordlist scan finishes, PathPlunderer visits the pages it found and extracts links from their HTML. Any URLs discovered this way that were not already in the wordlist scan results are shown with a `[CRAWL]` tag — 300s, 403s, and 500s included, 404s skipped.

---

## 📂 Dir Mode

### 📊 Output Format

Feroxbuster-style fixed-width columns for ultimate readability:

```text
  200  GET     65l     877w    5266c  [https://target.com/login.php](https://target.com/login.php)
  301  GET      2l      28w     169c  [https://target.com/admin](https://target.com/admin)  → [https://target.com/admin/](https://target.com/admin/)
  403  GET      0l       0w       0c  [https://target.com/secret](https://target.com/secret)  [CRAWL]

```

### 📈 Scan Phases

| Phase | Action | Flag |
| --- | --- | --- |
| **1** | **Server calibration** — latency, timeout, wildcard detection | *always* |
| **2** | **Dir scan** — wordlist × extensions, smart-recursive by default | *always* |
| **3** | **Crawl** — visit found pages, surface missed URLs (404 skipped) | *always* |
| **4** | **Probe** — 130+ known sensitive paths | `--probe` |
| **5** | **403 Bypass** — 100+ techniques | `--bypass-403` |
| **6** | **Secrets** — scan responses for leaked keys | `--secrets` |
| **7** | **Wayback** — query Wayback CDX API | `--wayback` |

### 💡 Examples

```bash
# Default — smart recurse on, crawl on, auto-loads wordlists/common.txt
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com)

# Full feature run
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com) \
  -w wordlists/directory-list-2.3-medium.txt -x php,html,txt \
  --probe --secrets --bypass-403 \
  --wayback --wayback-filter-status 200,301

# Bypass-only
python3 pathplunderer.py -m dir -u [https://target.com/admin](https://target.com/admin) --bypass-only

# Wayback dump
python3 pathplunderer.py -m dir -u [https://target.com](https://target.com) \
  --wayback-only --wayback-all --wayback-filter-status 200,301

# WP theme + plugin version detection
python3 pathplunderer.py -m dir -u [https://wpsite.com](https://wpsite.com) -x php --wp-detect

```

### 🛡️ 403 Bypass Techniques

* **Path variants:** `/admin/./` · `/admin//` · `/%2fadmin` · `/admin%00`
* **Encoding:** double-encode · Unicode · null bytes
* **HTTP headers:** `X-Forwarded-For` · `X-Original-URL` · `X-Rewrite-URL` · `X-Real-IP` · 20 more
* **IIS:** `/admin;param=value` · Tomcat path params · Spring Boot tricks
* **CDN:** Akamai and Cloudflare bypass headers

### 🔑 Secrets Detection

40+ patterns: AWS keys · GCP service accounts · private keys · JWTs · Stripe / Shopify / Twilio / SendGrid · Slack webhooks · GitHub / GitLab tokens · database connection strings · `.env` dumps.

### 🧩 WordPress Detection (`--wp-detect`)

While crawling found pages, PathPlunderer parses HTML source to identify WordPress themes and plugins along with their version numbers extracted from `?ver=` query parameters:

```text
  [WP-THEME]   twentytwentytwo                          ver:1.3
  [WP-PLUGIN]  contact-form-7                           ver:5.7.6
  [WP-PLUGIN]  woocommerce                              ver:8.2.1

```

---

## 🌍 Subdomain Mode

```bash
python3 pathplunderer.py -m subdomain \
  --domain target.com \
  -w wordlists/subdomains-top5000.txt \
  --resolver 8.8.8.8 \
  --check-cname \
  -t 200 -o subs.txt

```

---

## 🖥️ VHost Mode

```bash
python3 pathplunderer.py -m vhost \
  -u [http://10.10.11.100](http://10.10.11.100) \
  -w wordlists/vhosts.txt \
  --domain target.htb \
  --append-domain

# Filter same-size noise
python3 pathplunderer.py -m vhost \
  -u [https://10.10.10.5](https://10.10.10.5) \
  -w wordlists/subdomains-top5000.txt \
  --domain target.htb --xs 4242

```

---

## 🎯 Fuzz Mode

The `FUZZ` keyword works seamlessly in the URL, path, body, and headers.

```bash
# Path fuzzing
python3 pathplunderer.py -m fuzz \
  -u "[https://api.target.com/v1/user/FUZZ](https://api.target.com/v1/user/FUZZ)" \
  -w wordlists/api-endpoints.txt

# Credential brute-force via POST (like ffuf -d)
python3 pathplunderer.py -m fuzz \
  -u "[https://target.com/login](https://target.com/login)" \
  --data-urlencoded "user=admin&password=FUZZ" \
  -w wordlists/rockyou.txt -b 200

# JSON body fuzzing (Content-Type set automatically)
python3 pathplunderer.py -m fuzz \
  -u "[https://api.target.com/auth](https://api.target.com/auth)" \
  --data-json '{"user":"admin","pass":"FUZZ"}' \
  -w wordlists/passwords.txt -b 401

# Header fuzzing
python3 pathplunderer.py -m fuzz \
  -u "[https://target.com](https://target.com)" \
  -H "X-Api-Version: FUZZ" \
  -w wordlists/fuzz-general.txt

```

---

## ☁️ Cloud Mode

Methodology from **cloud_enum** and **lazys3** — generates keyword mutations and probes all three major cloud providers.

```bash
# Single keyword
python3 pathplunderer.py -m cloud -k acmecorp

# Multiple keywords + custom mutations
python3 pathplunderer.py -m cloud \
  -k acme -k acme-corp \
  -M wordlists/cloud_mutations.txt \
  -t 20

# Exact keywords only (no mutation expansion)
python3 pathplunderer.py -m cloud -k acmecorp --quickscan

```

### 📡 Endpoints Checked

| Provider | Coverage |
| --- | --- |
| **AWS S3** | 22 (virtual-hosted + path-style + all major regions + `-local` variant) |
| **GCP Storage** | 7 (googleapis.com, Firebase, App Engine) |
| **Azure** | 10 + DNS CNAME fingerprinting |

### 🚦 Status Indicators

| Status | Meaning |
| --- | --- |
| 🟢 `OPEN` | Bucket exists and lists files publicly |
| 🔒 `PRIVATE` | Bucket exists, authentication required |
| 🔵 `DNS-EXISTS` | CNAME resolves — Azure bucket exists even if HTTP is locked |

---

## 🔓 XML-RPC Mode

Brute-forces WordPress credentials via the `xmlrpc.php` endpoint using the `wp.getUsersBlogs` method. Based on the same technique as wpscan's XML-RPC attack.

```bash
# Single username + password list
python3 pathplunderer.py -m xmlrpc \
  -u [https://target.com](https://target.com) \
  -U admin \
  -P wordlists/rockyou.txt \
  -t 20

# Username list + password list
python3 pathplunderer.py -m xmlrpc \
  -u [https://target.com](https://target.com) \
  -U wordlists/users.txt \
  -P wordlists/passwords.txt \
  --stop-on-first

# Through Burp
python3 pathplunderer.py -m xmlrpc \
  -u [https://target.com](https://target.com) \
  -U admin -P passwords.txt \
  --burp -t 5

```

---

## 📚 Wordlists

`wordlists/common.txt` is **auto-loaded** when `-w` is not specified.

<details>
<summary><b>🔥 Click to expand Wordlist Download Commands</b></summary>




```bash
mkdir -p wordlists

# Dir scanning
curl -sL [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt) \
     -o wordlists/directory-list-2.3-medium.txt

curl -sL [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt) \
     -o wordlists/raft-large-words.txt

# Subdomain
curl -sL [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt) \
     -o wordlists/subdomains-top5000.txt

# VHost
curl -sL [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt) \
     -o wordlists/vhosts.txt

# API / Fuzz
curl -sL [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt) \
     -o wordlists/api-endpoints.txt

curl -sL [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/fuzz-Bo0oM.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/fuzz-Bo0oM.txt) \
     -o wordlists/fuzz-general.txt

```

</details>

---

## 🏷️ GitHub Topics (suggested)

```text
web-recon  directory-brute-force  fuzzer  403-bypass  subdomain-enumeration
cloud-security  aws-s3  wordpress-security  xmlrpc-bruteforce
penetration-testing  bug-bounty  ctf  python  security-tools

```

**Description for repository:**

> Multi-mode web attack surface discovery tool — directory brute-force with smart recursion, 403 bypass, Wayback Machine, cloud bucket enum (S3/GCP/Azure), WordPress XML-RPC brute-force, subdomain and vhost enumeration.

---

## ⚠️ Legal

> [!WARNING]
> **Authorized testing only.** Ensure you have explicit written permission before scanning any system. The author is not responsible for misuse.

---

<div align="center">
<i><b>PathPlunderer v4.1</b> · by Victor Azariah</i>




<i>Inspired by gobuster · feroxbuster · cloud_enum · lazys3 · SecLists</i>
</div>

```
