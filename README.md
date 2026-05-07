<div align="center">

<!-- Animated wave header -->
<img width="1728" height="986" alt="Screenshot 2026-05-07 at 1 43 46 AM" src="https://github.com/user-attachments/assets/8d2885e4-f389-4f7a-8a9f-dc78f5eb8f2f" width="100%" alt="PacketIQ Banner"/>

<!-- Animated typing SVG -->
<a href="https://github.com/PacketIQ">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3000&pause=800&color=3B82F6&center=true&vCenter=true&multiline=false&width=700&lines=Detect+Threats+in+Seconds+%F0%9F%94%8D;Generate+SIGMA+Rules+Automatically+%E2%9A%A1;Map+MITRE+ATT%26CK+Techniques+%F0%9F%8E%AF;AI+SOC+Copilot+%E2%80%94+Ask+Anything+About+Your+PCAP+%F0%9F%A4%96;Real-World+Detection.+Zero+False+Positives.+%E2%9C%85" alt="Typing SVG" />
</a>

<br/><br/>

<!-- Badges row 1 -->
![Python](https://img.shields.io/badge/Python-3.9%2B-3b82f6?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Engine-ef4444?style=for-the-badge&logo=python&logoColor=white)
![SIGMA](https://img.shields.io/badge/SIGMA-Rule%20Export-f97316?style=for-the-badge&logo=shield&logoColor=white)

<!-- Badges row 2 -->
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-eab308?style=for-the-badge&logo=target&logoColor=white)
![AI Copilot](https://img.shields.io/badge/AI%20Copilot-Gemini%20%7C%20Groq%20%7C%20Claude-10b981?style=for-the-badge&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-8b5cf6?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-60a5fa?style=for-the-badge)

<br/>

[**Features**](#-features) · [**Quick Start**](#-quick-start) · [**Web UI**](#-web-ui) · [**CLI**](#-cli-reference) · [**Detectors**](#-detection-capabilities) · [**MITRE**](#-mitre-attck-coverage) · [**AI Copilot**](#-ai-copilot) · [**Developer**](#-developer)

</div>

---

## 📡 What is PacketIQ?

**PacketIQ** is a professional-grade, AI-augmented PCAP analysis engine built for security analysts, threat hunters, and SOC teams. Upload any `.pcap`, `.pcapng`, or `.cap` capture file and get:

- **Threat detection** across 11 specialized detectors — zero configuration needed
- **Attack chain correlation** mapping multi-stage intrusions to kill chain phases
- **MITRE ATT&CK mapping** for every detected event
- **SIGMA rule generation** ready to import into Splunk, Elastic, Sentinel, QRadar
- **AI SOC Copilot** — ask natural language questions about the capture
- **Attribution engine** — links activity to known APT groups
- **Risk scoring** — quantified threat posture in seconds

> Built for real-world networks. Every threshold and filter has been calibrated against production traffic to eliminate false positives.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Detection Engine
- SSH / FTP / RDP / VNC / Telnet brute force
- TCP port scan & horizontal host scan
- C2 beacon periodicity detection (CV-based)
- DNS DGA anomaly with entropy analysis
- DNS tunneling (long subdomain exfil)
- JA3/JA3S TLS fingerprinting vs malware DB
- ICMP tunneling detection
- Cleartext credential exposure
- SMB to internet (EternalBlue / ransomware)
- Suspicious TCP flag combos (XMAS / NULL / FIN)
- Protocol misuse & non-standard ports

</td>
<td width="50%">

### 🧠 Intelligence Layer
- **Attack chain correlation** — links events into multi-stage campaigns
- **Kill chain mapping** — Reconnaissance → Actions on Objectives
- **MITRE ATT&CK tagging** — technique + tactic for every event
- **8 APT profile templates** — matched against TTPs
- **Attribution scoring** — confidence-weighted group attribution
- **Risk scoring** — 0–10 scale with tier classification
- **SIGMA rule generation** — auto-rendered YAML for any SIEM
- **Asset inventory** — all hosts, OS fingerprints, open ports

</td>
</tr>
<tr>
<td width="50%">

### 🌐 Web Interface
- Modern dark / light mode SOC dashboard
- Real-time WebSocket analysis progress
- Interactive threat events table with filters
- Attack chain visualiser with MITRE matrix
- Network intelligence & asset panels
- Timeline view with sparklines
- One-click SIGMA rule ZIP export
- AI chat panel with streaming responses

</td>
<td width="50%">

### ⚡ Performance
- Handles captures up to **10 GB**
- Tested on **100 K+ packet** captures
- Parallel detector pipeline
- Sliding-window O(n) algorithms
- Streaming SSE AI responses
- Auto-fallback across AI providers
- No cloud dependency — runs fully offline
- Pure Python — no native dependencies

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.9+   # Required
pip           # Package manager
```

### Installation

```bash
# 1 — Clone the repository
git clone https://github.com/PacketIQ/PacketIQ.git
cd PacketIQ

# 2 — Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3 — Install PacketIQ
pip install -e .

# 4 — Configure API keys (optional — for AI Copilot)
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY or GROQ_API_KEY (both free)
```

### Launch the Web App

```bash
packetiq webapp
# → Open http://localhost:8080
```

### Or use the CLI directly

```bash
packetiq analyze suspicious_traffic.pcap
```

---

## 🖥️ Web UI

<div align="center">

### Dashboard
> Risk score, kill chain coverage, protocol distribution, severity breakdown, top IPs

```
┌─────────────────────────────────────────────────────────────────┐
│  PacketIQ  v1.0 SIEM    capture.pcapng  82,248 pkts   CRITICAL  │
├──────────┬──────────────────────────────────────────────────────┤
│ Dashboard│  RISK SCORE: 8/10   ████████░░  CRITICAL             │
│ Threats  │                                                       │
│ Chains   │  Packets   Duration   Flows    DNS     SIGMA Rules    │
│──────────│  82,248    127.4s     1,204    892     12 generated   │
│ Network  │                                                       │
│ Assets   │  Kill Chain: [Recon] [Delivery] [Exploit] [C2] ←──  │
│──────────│                                                       │
│ SIGMA    │  Protocol Distribution     Severity Breakdown         │
│ Timeline │  ████ TCP 68%              ██ CRITICAL  3             │
└──────────┴──────────────────────────────────────────────────────┘
```

### AI Copilot Panel

```
┌─────────────────────────────────┐
│ 🤖 PacketIQ AI Copilot          │
│ Gemini 2.0 Flash · Free         │
├─────────────────────────────────┤
│ 📋 Summary  🔍 IOCs  ⏱ Timeline │
│ 🗺 MITRE    ⚡ Actions           │
├─────────────────────────────────┤
│ AI: I've analysed this capture. │
│ I detected 3 critical threats:  │
│ • SSH brute force from 1.2.3.4  │
│ • C2 beacon to 185.x.x.x:443   │
│ • DNS tunneling exfiltration    │
│                                 │
│ Ask me about the attack chain ▸ │
└─────────────────────────────────┘
```

</div>

---

## 📟 CLI Reference

PacketIQ ships with a full-featured terminal interface:

| Command | Description | Example |
|---------|-------------|---------|
| `analyze` | Full threat analysis with terminal report | `packetiq analyze dump.pcap` |
| `webapp` | Launch the web UI (default port 8080) | `packetiq webapp --port 9090` |
| `report` | Export analysis as markdown report | `packetiq report dump.pcap -o report.md` |
| `sigma` | Export SIGMA rules to YAML files | `packetiq sigma dump.pcap --out ./rules/` |
| `timeline` | Print chronological event timeline | `packetiq timeline dump.pcap --full` |
| `chat` | Interactive AI chat about the capture | `packetiq chat dump.pcap` |
| `dashboard` | Launch minimal local dashboard | `packetiq dashboard dump.pcap` |
| `fuse` | Analyse + report in one command | `packetiq fuse dump.pcap -o out.md` |
| `version` | Print version info | `packetiq version` |

### Common Options

```bash
packetiq analyze capture.pcap \
  --top 20 \               # Show top 20 IPs / ports
  --full \                 # Verbose output (all events)
  --alert \                # Send Telegram / WhatsApp alerts
  --alert-threshold HIGH   # Alert on HIGH and above
  --no-timeline            # Skip timeline section
```

---

## 🛡️ Detection Capabilities

| Detector | Method | False Positive Rate | Severity |
|----------|--------|-------------------|----------|
| **Brute Force** | SYN burst sliding window + avg bytes/connection | Very Low | HIGH → CRITICAL |
| **Port Scan** | Distinct dest-port count per src + time window | Very Low | MEDIUM → HIGH |
| **Host Scan** | Distinct dest-IP count per (src, dport) | Very Low | MEDIUM → HIGH |
| **C2 Beacon** | Coefficient of Variation on inter-arrival times | Low | HIGH → CRITICAL |
| **DNS DGA** | Shannon entropy + trusted domain whitelist | Very Low | HIGH |
| **DNS Tunneling** | Long subdomain label length analysis | Very Low | HIGH |
| **JA3 Fingerprint** | TLS ClientHello hash vs malware signature DB | Near Zero | CRITICAL |
| **ICMP Tunneling** | Total ICMP byte volume (≥ 100 KB threshold) | Very Low | MEDIUM → HIGH |
| **Credential Exposure** | Cleartext pattern matching in HTTP/FTP/Telnet | Low | HIGH → CRITICAL |
| **Suspicious TCP Flags** | RFC-violating flag combos (XMAS / NULL / FIN) | Near Zero | HIGH |
| **Protocol Misuse** | SMB to internet, cleartext external protocols | Very Low | HIGH → CRITICAL |

### Monitored Ports

```
Brute Force:   SSH(22)  FTP(21)  Telnet(23)  RDP(3389)  VNC(5900)
Cleartext:     FTP(21)  Telnet(23)
SMB Alert:     SMB(445)  NetBIOS(139)  → any external destination
C2 Beacon:     Any TCP/HTTP flow to external IPs with CV < 0.25
```

---

## 🗺️ MITRE ATT&CK Coverage

<div align="center">

| Tactic | Technique | Detector |
|--------|-----------|----------|
| **Reconnaissance** | T1046 Network Service Scanning | Port Scan |
| **Reconnaissance** | T1018 Remote System Discovery | Host Scan |
| **Command & Control** | T1071.001 Web Protocols | C2 Beacon |
| **Command & Control** | T1071.004 DNS | DNS Tunneling |
| **Command & Control** | T1573.002 Asymmetric Cryptography | JA3 Fingerprint |
| **Command & Control** | T1095 Non-Application Layer Protocol | ICMP Tunneling |
| **Credential Access** | T1110 Brute Force | Brute Force |
| **Credential Access** | T1552.001 Credentials in Files | Credential Exposure |
| **Exfiltration** | T1048 Exfiltration Over Alternative Protocol | DNS / ICMP Tunneling |
| **Lateral Movement** | T1021 Remote Services | SMB to Internet |
| **Defense Evasion** | T1036 Masquerading | Protocol Misuse |

</div>

---

## 🤖 AI Copilot

PacketIQ includes an AI-powered chat assistant that can answer any question about the analysed capture. It supports multiple providers with **automatic fallback** — if one hits its quota, the next kicks in seamlessly.

### Supported Providers

| Provider | Model | Cost | Limits |
|----------|-------|------|--------|
| **Google Gemini** | `gemini-2.0-flash` | 🆓 Free | 1,500 req/day |
| **Groq** | `llama-3.3-70b-versatile` | 🆓 Free | 30 req/min |
| **Anthropic** | `claude-sonnet-4-6` | 💳 Paid | API credits |

Auto-fallback chain: **Gemini → Groq → Anthropic**  
When Gemini's daily quota is hit, the system transparently switches to Groq mid-response.

### Configuration

```bash
# .env
GEMINI_API_KEY=AIza...      # Free — https://aistudio.google.com
GROQ_API_KEY=gsk_...        # Free — https://console.groq.com
ANTHROPIC_API_KEY=sk-ant-.. # Paid — https://console.anthropic.com
```

### Example Questions

```
"Walk me through the attack timeline from start to finish"
"List all IOCs found — IPs, domains, ports"
"What MITRE techniques are involved?"
"Which host is the most likely attacker?"
"What firewall rules should I create right now?"
"Is there any data exfiltration evidence?"
```

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        PacketIQ Pipeline                         │
│                                                                  │
│  ┌─────────┐    ┌──────────────┐    ┌───────────────────────┐   │
│  │  PCAP   │───▶│   Extractor  │───▶│   Detection Engine    │   │
│  │  File   │    │   (Scapy)    │    │                       │   │
│  └─────────┘    │              │    │  ┌─────────────────┐  │   │
│                 │ • Flows       │    │  │ BruteForce      │  │   │
│                 │ • TCP SYNs   │    │  │ PortScan        │  │   │
│                 │ • DNS        │    │  │ HostScan        │  │   │
│                 │ • HTTP       │    │  │ C2Beacon        │  │   │
│                 │ • TLS/JA3    │    │  │ DNSAnomaly      │  │   │
│                 │ • ICMP       │    │  │ JA3Fingerprint  │  │   │
│                 └──────────────┘    │  │ ProtocolMisuse  │  │   │
│                                     │  │ CredExposure    │  │   │
│                                     │  │ ICMPTunneling   │  │   │
│                                     │  └─────────────────┘  │   │
│                                     └───────────┬───────────┘   │
│                                                 │               │
│                 ┌───────────────────────────────▼─────────────┐ │
│                 │            Correlation Engine                │ │
│                 │  • Attack chain linking                      │ │
│                 │  • Kill chain phase assignment               │ │
│                 │  • MITRE ATT&CK mapping                     │ │
│                 │  • APT attribution scoring                   │ │
│                 └───────────────────┬─────────────────────────┘ │
│                                     │                           │
│          ┌──────────────────────────▼──────────────────────┐    │
│          │                   Output Layer                   │    │
│          │  ┌──────────┐  ┌───────────┐  ┌─────────────┐  │    │
│          │  │ Web UI   │  │ SIGMA     │  │  CLI Report  │  │    │
│          │  │ FastAPI  │  │ Generator │  │  Terminal UI │  │    │
│          │  │ + AI Chat│  │ YAML/ZIP  │  │  Markdown    │  │    │
│          │  └──────────┘  └───────────┘  └─────────────┘  │    │
│          └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration

### Environment Variables (`.env`)

```bash
# ── AI Copilot ────────────────────────────────────────
GEMINI_API_KEY=AIza...           # Google Gemini 2.0 Flash (free)
GROQ_API_KEY=gsk_...             # Groq Llama 3.3 70B (free)
ANTHROPIC_API_KEY=sk-ant-...     # Claude (paid)

# ── Telegram Alerts ───────────────────────────────────
TELEGRAM_BOT_TOKEN=...           # From @BotFather
TELEGRAM_CHAT_ID=...             # Your chat ID

# ── WhatsApp via Twilio (optional) ────────────────────
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
TWILIO_WHATSAPP_TO=whatsapp:+91xxxxxxxxxx
```

### Supported File Formats

| Format | Extension | Max Size |
|--------|-----------|----------|
| Wireshark / tcpdump | `.pcap` | 10 GB |
| Next-gen PCAP | `.pcapng` | 10 GB |
| Generic capture | `.cap` | 10 GB |

---

## 📦 Project Structure

```
PacketIQ/
├── packetiq/
│   ├── cli.py                    # CLI entry point (Click)
│   ├── extractor/
│   │   └── data_extractor.py     # Scapy-based packet parser
│   ├── detection/
│   │   ├── engine.py             # Parallel detector orchestrator
│   │   ├── brute_force.py        # SSH/FTP/RDP/VNC/Telnet brute force
│   │   ├── port_scan.py          # Port + host scan detection
│   │   ├── beacon.py             # C2 beacon periodicity (CV-based)
│   │   ├── dns_anomaly.py        # DGA entropy + DNS tunneling
│   │   ├── ja3.py                # TLS JA3 fingerprint matching
│   │   ├── credential.py         # Cleartext credential detection
│   │   ├── protocol_misuse.py    # ICMP tunnel, SMB, suspicious flags
│   │   ├── fingerprint.py        # OS / service fingerprinting
│   │   ├── risk_scorer.py        # Risk 0–10 scoring engine
│   │   └── models.py             # DetectionEvent, Severity, EventType
│   ├── correlation/
│   │   └── engine.py             # Attack chain + attribution
│   ├── sigma/
│   │   └── generator.py          # SIGMA YAML rule generation
│   ├── utils/
│   │   └── helpers.py            # IP classification, formatting
│   └── webapp/
│       ├── app.py                # FastAPI backend + AI streaming
│       └── templates/
│           └── index.html        # Full SPA web interface
├── tests/                        # Test suite
├── samples/                      # Sample PCAP files
├── requirements.txt
├── setup.py
└── .env.example
```

---

## 🧪 Running Tests

```bash
# Run full test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=packetiq --cov-report=html

# Quick syntax check all modules
python -m py_compile packetiq/detection/*.py
```

---

## 📋 SIGMA Rule Example

PacketIQ auto-generates production-ready SIGMA rules for every detected threat:

```yaml
title: Brute Force Attack on SSH from 192.168.1.100
id: a3f2e1b0-4c5d-6e7f-8a9b-0c1d2e3f4a5b
status: experimental
description: >
    Brute-force SSH login attempts from 192.168.1.100 — 47 attempts detected.
    Auto-generated by PacketIQ.
author: PacketIQ
logsource:
    category: authentication
detection:
    selection:
        src_ip: '192.168.1.100'
        dst_port: 22
        event_type: 'authentication_failure'
    timeframe: 60s
    condition: selection | count() by src_ip > 6
falsepositives:
    - Misconfigured automation
    - Password reset loops
level: high
tags:
    - attack.credential_access
    - attack.t1110
    - attack.t1110.001
```

Export all rules as a ZIP:
```bash
packetiq sigma capture.pcap --out ./sigma_rules/
```

---

## 📊 Performance Benchmarks

| Capture Size | Packets | Analysis Time | Memory |
|-------------|---------|---------------|--------|
| 5 MB | ~8,000 | ~2s | ~60 MB |
| 16 MB | ~30,000 | ~5s | ~90 MB |
| 61 MB | ~82,000 | ~12s | ~160 MB |
| 108 MB | ~107,000 | ~19s | ~220 MB |

*Benchmarked on Apple M-series. Results vary by capture complexity.*

---

## 🔐 Security & Privacy

- **No data leaves your machine** — all analysis runs locally
- PCAP files are processed in memory and never written to disk permanently
- AI Copilot sends only the *structured analysis summary* to the AI API — raw packets are never transmitted
- API keys are stored only in your local `.env` file

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

```bash
# 1. Fork and clone
git clone https://github.com/your-username/PacketIQ.git

# 2. Create a feature branch
git checkout -b feature/my-new-detector

# 3. Make changes and add tests

# 4. Run the test suite
python -m pytest tests/ -v

# 5. Open a Pull Request
```

### Contribution Areas

- 🔍 **New detectors** — add to `packetiq/detection/`
- 🧠 **APT profiles** — extend the attribution database
- 🌍 **Trusted domain list** — improve CDN whitelisting in `dns_anomaly.py`
- 📊 **Visualizations** — enhance dashboard charts
- 🧪 **Tests** — increase coverage
- 🌐 **Translations** — UI localization

---

## 🛡️ Alert Integrations

```bash
# Analyze and alert via Telegram for HIGH+ threats
packetiq analyze capture.pcap --alert --alert-threshold HIGH
```

| Integration | Status | Setup |
|-------------|--------|-------|
| Telegram | ✅ Built-in | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` in `.env` |
| WhatsApp | ✅ Built-in | Twilio credentials in `.env` |
| Email | 🔜 Planned | — |
| Slack | 🔜 Planned | — |

---

## 📄 License

```
MIT License — Copyright (c) 2025 Jatin Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, subject to the conditions of the MIT License.
```

---

## 👨‍💻 Developer

<div align="center">

<br/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=15&duration=2500&pause=1000&color=60A5FA&center=true&vCenter=true&width=550&lines=Jatin+Kumar+%E2%80%94+Cybersecurity+Researcher;Threat+Hunter+%7C+Network+Forensics+%7C+SOC+Tooling;Building+real-world+defensive+intelligence+tools" alt="Developer Typing"/>

<br/><br/>

| Field | Info |
|:------|:-----|
| 👤 **Name** | Jatin Kumar |
| 🛡️ **Role** | Cybersecurity Researcher |
| 🔬 **Focus** | Threat Hunting · Network Forensics · SOC Tooling · Malware Analysis |
| 🌐 **Portfolio** | [ogxodin.netlify.app](https://ogxodin.netlify.app) |

<br/>

[![Portfolio](https://img.shields.io/badge/🌐%20Portfolio-ogxodin.netlify.app-3b82f6?style=for-the-badge)](https://ogxodin.netlify.app)
[![GitHub](https://img.shields.io/badge/GitHub-PacketIQ-171515?style=for-the-badge&logo=github&logoColor=white)](https://github.com/PacketIQ)

<br/>

> *PacketIQ was built to bring production-grade network forensics to every security team — from solo analysts to enterprise SOCs.*
> *If it helped you catch something real, drop a ⭐ — it means everything.*

<br/>

</div>

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:3b82f6,100:0b0f1a&height=100&section=footer&animation=fadeIn" width="100%" alt="Footer Wave"/>

<sub>Made with ❤️ and a lot of PCAP files &nbsp;·&nbsp; PacketIQ v1.0.0 &nbsp;·&nbsp; MIT License</sub>

</div>
