<div align="center">

```
███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
████╗  ██║██║   ██║██║     ██║         ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
██╔██╗ ██║██║   ██║██║     ██║         ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
██║╚██╗██║██║   ██║██║     ██║         ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
██║ ╚████║╚██████╔╝███████╗███████╗    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
```

### AI-Powered Autonomous Security Platform

[![Version](https://img.shields.io/badge/version-5.0-red.svg?style=for-the-badge)](https://github.com/rajatayyabb)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg?style=for-the-badge)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Ubuntu-black.svg?style=for-the-badge)](https://www.kali.org/)

**Free. Self-Hosted. No Data Leaves Your Network.**

*Developed by **Tayyab** | BS Cybersecurity | CASE Institute of Technology*

[🚀 Install](#-installation) · [📋 Features](#-features) · [🔌 MCP](#-mcp-tools) · [🧠 Odysseus](#-odysseus--natural-language-interface) · [🗺️ Roadmap](#️-roadmap)

</div>

-----

## What is NullShadow?

NullShadow is a **free, self-hosted AI security platform** that gives you enterprise-grade vulnerability monitoring, threat-intelligence correlation, predictive analytics and AI-guided remediation — without paying for CrowdStrike, Darktrace or Tenable.

It does things most security tools don’t:

1. **Continuous defensive monitoring** — runs on a schedule, tracks how your posture changes over time, alerts when risk increases, and explains exactly how to fix each finding.
2. **Predictive intelligence** — predicts *when* a CVE will be weaponized for your specific tech stack, and compares your live profile against real breach fingerprints.
3. **Compliance evidence generation** — maps findings to ISO 27001, NIST CSF 2.0 and PCI DSS v4.0 controls and generates audit-ready PDFs from real scan data.

> “You have been exposed to this critical CVE for 47 days” is more actionable than a list of CVE IDs.

-----

## ✨ What’s New in v5.0

| Feature | Description |
|---|---|
| 🧠 **Odysseus Integration** | Natural-language front end — type “scan this domain” and the agent calls NullShadow’s MCP tools autonomously |
| 🕰️ **Security Posture Time Machine** | Exact days exposed per CVE (NVD publish date + first-seen scan date) |
| 📡 **Real-Time Threat Intel** | CISA KEV + AlienVault OTX + abuse.ch ThreatFox; KEV match forces CRITICAL |
| 🔮 **Cognitive Attack Prediction** | Probability + days-until-weaponized per CVE, from NVD→CISA-KEV timing patterns |
| 🧬 **Security DNA** | Compares your live fingerprint against pre-breach patterns (MOVEit, Log4Shell, ProxyLogon…) |
| 👁️ **Sentinel Mode** | Autonomous CVE watcher — polls NVD hourly, matches your tech stack, pushes alerts via ntfy.sh |
| 🟣 **AI Attack Narrative** | Purple-team attack-path write-up with one Priority Action (no exploit code) |
| 🤖 **AI System Pentesting** | OWASP LLM Top 10 — prompt-injection / endpoint-discovery / prompt-leak (detection only) |
| 🌐 **Scan Engine** | Nikto + WhatWeb + Dirb + 5-step hash crack + SQLi detection, all feeding the findings pipeline |
| 📜 **Compliance Evidence Generator** | Auto ISO 27001 / NIST CSF / PCI DSS / OWASP audit PDFs |
| 🔁 **Self-Healing Remediation** | Verifies whether advice worked; gives a *different* follow-up when a fix didn’t take |
| 📈 **Security-Debt Forecasting** | Linear-regression posture projection (refuses to guess with <10 runs) |

-----

## 🎯 Features

**45 active tools** across pentesting, OSINT, AI/utilities, defensive monitoring and predictive intel.

<details>
<summary><b>Pentesting & Scan Engine</b></summary>

| # | Tool | What it does |
|---|---|---|
| 01 | Port Scanner | TCP/UDP scan with service fingerprinting (nmap) |
| 02 | Vulnerability Scanner | CVE detection via nmap NSE scripts |
| 03 | Host Discovery | ARP/ICMP sweep |
| 04 | IP Pinger | ICMP latency / reachability |
| 05 | Dir Bruteforcer | Web directory enumeration (Dirb + extensions) |
| 06 | SSL/TLS Auditor | Cipher, cert chain, expiry, TLS version |
| 07 | Hash ID & Cracker | Hash type ID + wordlist cracking |
| 08 | JWT Analyzer | JWT decode + weakness detection |
| 09 | Subdomain Enumerator | DNS brute-force + passive |
| 10 | DNS Recon | A/AAAA/MX/TXT/NS/SOA |
| 11 | HTTP Header Analyzer | Security-header audit |
| 37 | **Full Web Scan** | Nikto + WhatWeb + Dirb combined |
| 38 | **Nikto** | Web-server misconfigs / dangerous files |
| 39 | **WhatWeb** | CMS/framework tech fingerprint |
| 40 | **Hash Crack (5-step chain)** | Hashcat GPU→CPU→mask→John→built-in (never errors) |
| 41 | **SQLi Detection** | Error + time-based parameter detection (detection only) |

</details>

<details>
<summary><b>OSINT & Utilities</b></summary>

| # | Tool |
|---|---|
| 12 | Domain WHOIS (IANA RDAP, all TLDs incl. .edu.pk/.gov.pk) |
| 13 | Username Tracker (30+ platforms) |
| 14 | IP Geolocation · 15 Phone Lookup · 16 Email Harvester · 17 CVE Search |
| 18 | URL Phishing Analyzer · 19 Website Cloner · 20 Cookie Auditor |
| 21 | Network Info · 22 Password Generator |

*IoT/firmware modules (old [23][24]) are retained in the codebase but hidden from the menu — NullShadow’s focus is network/web pentesting and defensive monitoring.*

</details>

<details>
<summary><b>Defensive Monitoring & Predictive Intel</b></summary>

| # | Tool | What it does |
|---|---|---|
| 26 | Auto Full Recon | 7-phase autonomous recon |
| 34 | Scan Diff | New/resolved/changed findings + risk delta |
| 35 | Guided Remediation | CWE/OWASP mapping + fix + secure snippet |
| 36 | Findings + CVE Enrich | Live NVD enrichment (CVSS, description, dates) |
| 42 | **Time Machine** | Days exposed per CVE |
| 43 | **Threat Intel** | CISA KEV + OTX + ThreatFox |
| 44 | **AI System Pentest** | OWASP LLM Top 10 |
| 45 | **Attack Narrative** | Purple-team attack path |
| 46 | **Attack Prediction** | When a CVE will be weaponized |
| 47 | **Security DNA** | Breach-pattern matching |
| 48 | **Sentinel Mode** | Autonomous CVE watcher + ntfy push |
| 49 | **Compliance Report** | ISO27001 / NIST / PCI / OWASP PDF |
| 50 | **Posture Forecast** | Security-debt projection |
| 51 | **Remediation Verify** | Self-healing effectiveness loop |

</details>

### AI Modes

| Mode | Backend | Cost |
|---|---|---|
| Local (default) | Ollama — llama3.2:3b / qwen2.5:7b | **Free** |
| Cloud (optional) | Claude / GPT-4 / Gemini | Pay-per-use |
| MCP Agent | Any MCP client (Claude Desktop, Odysseus) | Free |

-----

## 🚀 Installation

Tested on **Kali Linux 2025.x** (also works on Ubuntu 22.04+).

### 1 · System dependencies + scanning tools

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip python3-dev \
     build-essential libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev \
     nmap nikto whatweb dirb hashcat john
```
*(On Kali full, most scanning tools are pre-installed — this just makes sure.)*

### 2 · Clone + Python environment

```bash
git clone https://github.com/rajatayyabb/NullShadow-v5.git NullShadow-v5
cd NullShadow-v5

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3 · Config (no API key required — local AI is the default)

```bash
[ -f config/config.py ] || cp config/config.example.py config/config.py
```
All core features work with **zero** API keys. `DEFAULT_AI=local`, and the SQLite DB is created automatically on first run.

### 4 · (Recommended) Local AI — free & offline

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
```
Skip this and NullShadow still runs (rule-based fallback for AI features).

### 5 · Run

```bash
source venv/bin/activate        # every new terminal

python3 main.py                 # CLI — 45-tool menu
python3 dashboard.py            # dashboard → http://127.0.0.1:8077
python3 mcp_server.py           # MCP server (stdio) for AI agents
```

### 6 · Sanity test (no external tools or network needed)

```bash
python3 modules/intel/time_machine.py
python3 modules/intel/security_dna.py
python3 modules/compliance/evidence_generator.py
python3 modules/pentesting/scan_engine.py
```

Then run a real scan against something you own or are authorized to test
(e.g. `scanme.nmap.org`, or your own Metasploitable2 VM):

```bash
python3 main.py        # → [37] Full Web Scan   or   [26] Auto Full Recon
```

### Optional · Connect Claude Desktop via MCP

```jsonc
// ~/.config/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "nullshadow": {
      "command": "python3",
      "args": ["/absolute/path/to/NullShadow-v5/mcp_server.py"]
    }
  }
}
```

### Optional · Cloud AI keys (not required)

```bash
nano config/config.py
```

| Provider | Key | Link |
|---|---|---|
| Anthropic (Claude) | `ANTHROPIC_API_KEY` | https://console.anthropic.com |
| OpenAI (GPT-4) | `OPENAI_API_KEY` | https://platform.openai.com |
| Google (Gemini) | `GEMINI_API_KEY` | https://aistudio.google.com |

-----

## 🧠 Odysseus — Natural-Language Interface

Drive NullShadow in plain English through [Odysseus](https://github.com/pewdiepie-archdaemon/odysseus), a self-hosted AI workspace that acts as an MCP client. With a local model this is **100% free**.

```bash
# NullShadow core + dashboard + ollama
docker compose -f docker-compose.v5.yml up -d

# Odysseus UI (host port 7011; the container itself listens on 7000)
git clone https://github.com/pewdiepie-archdaemon/odysseus.git nullshadow_ui
cd nullshadow_ui && cp .env.example .env && docker compose up -d --build && cd ..

# Open http://localhost:7011 → create the admin account → then register NullShadow:
python3 docker/register_nullshadow_mcp.py \
    --odysseus-url http://localhost:7011 --username admin --password '<your-pw>'
```

Registration posts form-encoded to the real `POST /api/mcp/servers` endpoint.
Other auth modes: `--internal-token "$ODYSSEUS_INTERNAL_TOKEN"` or, if Odysseus runs
with `AUTH_ENABLED=false`, `--no-auth`. See `docker/register_nullshadow_mcp.py`.

> **License note:** Odysseus is **AGPL-3.0**. Self-hosting for your FYP/demo is fine;
> if you rebrand/modify it and serve it on a *public* server, AGPL requires you to
> offer that modified source to its users. (NullShadow itself is your own project.)

-----

## 🔌 MCP Tools

NullShadow exposes **15 tools** via Model Context Protocol (Claude Desktop, Odysseus, Cursor, Roo Code):

```
# core
port_scan(target)             vulnerability_scan(target)   subdomain_enum(target)
dns_recon(target)             whois_lookup(domain)         hash_crack(hash)
jwt_analyze(token)

# v5.0 predictive & defensive intel
threat_intel_check(target)          exposure_analysis(target)
predict_exploitation(target)        dna_analysis(target)
generate_attack_narrative(target)   compliance_report(target, framework)
forecast_posture(target)            sentinel_status()
```

-----

## 🏗️ Architecture

```
NullShadow v5.0
├── main.py                              ← CLI entry point (45 tools)
├── mcp_server.py                        ← MCP server (15 tools)
├── dashboard.py                         ← Flask dashboard (port 8077) + v5 routes
├── docker-compose.v5.yml / Dockerfile   ← core + dashboard + ollama
├── docker/register_nullshadow_mcp.py    ← Odysseus MCP registration
├── modules/
│   ├── ai/            ← cloud + local (Ollama) AI engines, RL/DL orchestrator
│   ├── pentesting/
│   │   ├── scanner.py            ← core pentest tools
│   │   ├── scan_engine.py        ← Nikto/WhatWeb/Dirb/HashCrack/SQLi (v5)
│   │   └── ai_pentest.py         ← OWASP LLM Top 10 (v5)
│   ├── osint/ · recon/ · reporting/
│   ├── compliance/               ← mapper + evidence PDF generator (v5)
│   └── intel/
│       ├── nvd_lookup.py · scan_diff.py · risk_score.py · remediation.py · exploit_refs.py
│       ├── time_machine.py       ← days-exposed per CVE (v5)
│       ├── threat_feeds.py       ← CISA KEV / OTX / ThreatFox (v5)
│       ├── attack_prediction.py  ← weaponization prediction (v5)
│       ├── security_dna.py       ← breach-pattern matching (v5)
│       ├── attack_narrative.py   ← purple-team narrative (v5)
│       ├── sentinel.py           ← autonomous CVE watcher (v5)
│       └── remediation_tracker.py← self-healing loop (v5)
└── null_db/db.py                 ← SQLite (scans + findings + CVE/threat cache)
```

-----

## 📊 Why NullShadow?

| Capability | NullShadow | Nessus | CrowdStrike | Manual Pentest |
|---|:--:|:--:|:--:|:--:|
| Vulnerability Scanning | ✅ | ✅ | ✅ | ✅ |
| Continuous Monitoring | ✅ | ✅ | ✅ | ❌ |
| AI-Guided Remediation | ✅ | ❌ | ❌ | ❌ |
| **CVE Weaponization Prediction** | ✅ | ❌ | ❌ | ❌ |
| **Breach-Pattern Matching (Security DNA)** | ✅ | ❌ | ❌ | ❌ |
| Autonomous CVE Watcher | ✅ | ❌ | ✅ | ❌ |
| Local AI (no cloud cost) | ✅ | ❌ | ❌ | ❌ |
| MCP Agent Integration | ✅ | ❌ | ❌ | ❌ |
| ISO27001 / NIST / PCI Evidence | ✅ | ❌ | ❌ | ✅ |
| AI System Pentesting (OWASP LLM) | ✅ | ❌ | ❌ | ❌ |
| **Cost** | **Free** | $3,990+/yr | $15/endpoint/mo | $500+/report |

-----

## 🗺️ Roadmap

### v5.0 — Current ✅
45-tool CLI · predictive intel (prediction, DNA, time machine) · threat feeds ·
AI system pentesting · compliance evidence · Sentinel mode · Odysseus NL interface ·
upgraded dashboard · 15 MCP tools.

### v6.0 — Ideas 🔧
Scheduled multi-target monitoring UI · blast-radius asset graph · more breach
fingerprints · Slack/Discord alerting · report templating.

-----

## ⚠️ Disclaimer

NullShadow is for **educational purposes and authorized security testing only**.
Always obtain explicit written permission before scanning any system or network you
do not own. The AI System Pentesting module must only be used on AI systems you are
explicitly authorized to test. The developer is not responsible for misuse.

**Use responsibly. Test ethically.**

-----

<div align="center">

Made with 🖤 by **Tayyab**

*BS Cybersecurity | CASE Institute of Technology*

*“In the void, shadows speak. In the code, intelligence leads.”*

⭐ If NullShadow helped you, consider starring the repo

</div>
