# 🛡️ Security Operations Center (SOC) Projects

This repository contains multiple **SOC (Security Operations Center) projects** demonstrating hands-on experience in threat detection, log monitoring, incident response, and security automation.

The projects replicate real-world SOC workflows using open-source and commercial tools such as **Wazuh, Splunk, ELK Stack, Snort, Suricata, and Wireshark**.

---

## 🎯 Objectives
- Build SOC lab environments for practicing cybersecurity monitoring.
- Collect and analyze logs from different endpoints and network sources.
- Detect threats such as brute-force, malware, insider abuse, and network scanning.
- Develop SOC workflows: **Detection → Investigation → Response → Reporting**.
- Create reusable playbooks, queries, and dashboards for SOC analysis.

---

## 📂 Projects Overview

### 1. **SIEM Setup & Log Collection**
- Tools: Wazuh, Splunk, ELK
- Collect logs from Windows, Linux, and web servers.
- Normalize logs for easier searching and correlation.

### 2. **Intrusion Detection & Alerts**
- Tools: Snort
- Detect suspicious network traffic such as port scans, brute-force attempts, and exploits.
- Integrate alerts into SIEM dashboards.

### 3. **SOC Use Cases**
- 🔑 Brute force login detection (SSH, RDP, web).
- 🌐 Web attack monitoring (SQL injection, XSS).
- 🦠 Malware & persistence detection.
- 📡 Reconnaissance & port scanning alerts.
- 🧑‍💻 Insider threat & privilege escalation detection.

### 4. **Incident Response**
- Investigate alerts using SIEM dashboards.
- Correlate events across multiple data sources.
- Document incidents in structured reports.

### 5. **Threat Hunting**
- Create custom queries to proactively search for anomalies.
- Look for unusual login times, rare processes, or network connections.

### 6. **Dashboards & Reporting**
- Build SOC dashboards for real-time monitoring.
- Export reports in HTML, PDF, or CSV formats for documentation.

---

## ⚙️ Tools & Technologies
- **SIEM/XDR:** Wazuh, Splunk, ELK Stack (Elasticsearch, Logstash, Kibana)
- **IDS/IPS:** Snort
- **Log Shippers:** Filebeat, Winlogbeat, Syslog
- **Network Analysis:** Wireshark, tcpdump
- **Attack Simulation:** Kali Linux (Nmap, Hydra, Metasploit)

---
