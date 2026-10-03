# 🛡️ SOC Analyzer — Security Operations Center & Threat Hunting Platform

**SOC Analyzer** is a security log analysis and automated incident investigation platform. Designed for SOC analysts, incident response teams, and threat hunters, it ingests multi-source logs, extracts Indicators of Compromise (IOCs), correlates distributed attack chains, maps actions to the **MITRE ATT&CK® framework**, and provides a dark-themed analytical dashboard.

---

## 🚀 Key Features

- 📑 **Multi-Format Ingestion**:
  - Linux `auth.log` / `syslog`
  - Web Server Access Logs (Apache / Nginx Combined)
  - Firewall & Packet Filter Logs (`iptables`, pf, generic firewalls)
  - Windows Event Log (`Security.xml`)
  - Structured JSON Network Flows (NetFlow / Zeek / Suricata)
- 🎯 **Advanced Threat Detection Engine**:
  - SSH / RDP Brute Force Detection
  - Web Attacks: SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Command Injection
  - Known Attacker Tool Signatures (`sqlmap`, `nikto`, `nmap`, etc.)
  - Privilege Escalation (`sudo`, `su`, setuid changes)
  - Command & Control (C2) Beaconing & DNS Tunneling
  - Port Scanning & Internal Reconnaissance
- 🔍 **Automated IOC Extraction**:
  - Public & Private IPv4 / IPv6 addresses
  - Domains, FQDNs, and URLs
  - File Hashes (MD5, SHA-1, SHA-256)
  - Target email addresses and Windows registry keys
- 📊 **Statistical Anomaly Detection**:
  - Volume spike detection via Z-Score algorithm
  - Interquartile Range (IQR) detection for skewed request distributions
  - Off-hours / anomalous login time analysis
- 🗺️ **MITRE ATT&CK® Matrix Mapping**:
  - Maps detected threats directly to Tactics & Techniques (Initial Access, Execution, Persistence, Credential Access, Defense Evasion, Exfiltration, etc.)
  - Visual matrix heatmap highlighting attack surface coverage.
- 🔗 **Incident Correlation Engine**:
  - Correlates multi-stage events into coherent attack chains (e.g., Scan → Exploit → Privilege Escalation → Exfiltration).
- 📑 **Executive Reporting**:
  - One-click HTML incident reports complete with metrics, attack graphs, and remediation advice.

---

## 📁 Directory Structure

```
soc-analyzer/
├── app.py                      # Flask web application & API entry point
├── config.py                   # Central settings, severity weights & thresholds
├── requirements.txt            # Python dependencies
├── core/
│   ├── log_parser.py           # Multi-format normalization engine
│   ├── threat_detector.py      # Rule-based threat matching engine
│   ├── ioc_extractor.py        # Regex-based IOC discovery
│   ├── anomaly_detector.py     # Statistical deviation & z-score models
│   ├── mitre_mapper.py         # MITRE ATT&CK mapping database
│   ├── correlator.py           # Attack chain reconstruction
│   ├── geo_lookup.py           # IP geolocation & risk scoring
│   └── report_generator.py     # Executive HTML report generator
├── rules/
│   └── default_rules.yaml      # Declarative detection rules
├── sample_logs/
│   ├── auth_syslog.log         # Sample brute force & escalation
│   ├── apache_access.log       # Sample SQLi, XSS, and traversal attacks
│   ├── firewall.log            # Sample port scanning
│   ├── windows_security.xml    # Sample Windows event logs
│   └── network_flow.json       # Sample C2 beaconing & tunneling
├── templates/                  # Dark-themed dashboard HTML templates
├── static/                     # CSS & Chart.js scripts
└── tests/
    └── test_analyzer.py        # Unit test suite
```

---

## ⚡ Quickstart

### 1. Install Requirements
```bash
cd soc-analyzer
pip install -r requirements.txt
```

### 2. Launch the Web Platform
```bash
python3 app.py
```

Open your browser to: **`http://127.0.0.1:5000`**

### 3. Immediate Testing with Sample Logs
Navigate to the **Upload Logs** page on the dashboard and select any log from `sample_logs/` (e.g., `apache_access.log` or `auth_syslog.log`) to immediately see live detections, MITRE ATT&CK heatmap mappings, and IOC extractions.

---

## 🧪 Running Tests
```bash
python3 -m unittest discover tests
```
