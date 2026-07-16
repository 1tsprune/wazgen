<div align="center">

![WAZGEN](https://img.shields.io/badge/WAZGEN-v2.0-34d399?style=for-the-badge&logo=wazuh&logoColor=white)
<br>
**Wazuh Rule Generator** — Paste any log, get Wazuh XML rule + decoder instantly.

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![Wazuh](https://img.shields.io/badge/Wazuh-34d399?style=flat-square&logo=wazuh&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-EB0028?style=flat-square&logo=mitre&logoColor=white)

<br>

```
   __      __     ______      _____  ______  _   __
  / /____ / /__  / ____/___  / __  |/ __ \ \ | / /
 / __/ _  / _ \/ / __/ __ \/ /_/ / / /_/ /  |/ / 
/ /_/  __/  __/ /_/ / /_/ /  __,_/ \__, / /|  /  
\__/\___/\___/\____/\____/_/     /____/_/ |_/   
                                                 
```

<br>

**Paste any log → auto-generate Wazuh XML rule + decoder + MITRE ATT&CK mapping.**  
Supported 100+ log patterns, smart parser for unknown logs, batch processing, rule history, dark/light mode.

🇮🇩 *Tempel log sampel → dapatkan rule Wazuh XML + decoder + MITRE ATT&CK secara otomatis.  
Mendukung 100+ pola log, smart parser untuk log yang tidak dikenal, proses batch, riwayat rule, mode gelap/terang.*

</div>

---

## ✨ Features

| Feature | Description |
|---|---|
| **Rule Generator** | Paste any log sample, get Wazuh XML rule + decoder + ossec.conf |
| **Smart Parser** | Auto-detect log format (syslog, JSON, key=value, Windows Event, HTTP) |
| **100+ Patterns** | Built-in database of common logs across 13 categories |
| **Batch Processing** | Upload multi-line log file, generate multiple rules at once |
| **MITRE ATT&CK** | 20+ technique tags, selectable per rule |
| **Rule Validation** | Check XML syntax before deployment |
| **Rule Editor** | Edit generated XML directly in the browser |
| **Rule History** | Auto-save last 50 rules in localStorage |
| **Dark/Light Mode** | Theme toggle with system preference persistence |
| **Install Scripts** | Ready-to-use scripts for Wazuh server & agent installation |
| **Workspace** | Collect rules and export multi-file ZIP pack for manager |
| **ZIP Pack** | One-click rule+decoder+ossec+README download |
| **Command Palette** | Ctrl+K actions |
| **Rule Linter** | Deployability checks after generate |
| **AI Assist** | Optional Gemini API (key stays in browser) |
| **PWA** | Offline-capable service worker |

## 🗄️ Database Coverage

| Category | Count | Examples |
|---|---|---|
| Authentication | 13 | SSH, Sudo, PAM, FTP, RADIUS, LDAP, Vault |
| Firewall | 10 | IPTables, nftables, Firewalld, **FortiGate**, **Cisco ASA**, **Palo Alto**, **pfSense**, **Sophos** |
| Web | 12 | Squid, Apache, Nginx, HAProxy, IIS, Tomcat, Caddy, **Cloudflare** |
| Cloud | 7 | AWS CloudTrail, **Azure AD**, **Azure NSG**, **GCP Audit** |
| Windows | 15 | 4624/4625/4688/7045/4732/4698/4104, Sysmon, Defender, AppLocker |
| IDS/IPS | 5 | Suricata, Snort, OSSEC, Wazuh Agent |
| Database | 6 | MySQL, PostgreSQL, **MSSQL**, **MongoDB**, **Redis**, **Elasticsearch** |
| Network | 6 | Zeek, DNS, DHCP, **OpenVPN**, **WireGuard** |
| Email | 5 | Postfix, **Dovecot**, **SpamAssassin**, **MS Exchange**, MailScanner |
| Container | 3 | Docker, Kubernetes exec, K8s ConfigMap |
| Malware | 1 | WebShell detection |
| Other | 5 | Cron, SELinux, MISP, fail2ban, CrowdSec |

## 🚀 Quick Start

### 🌐 Live Demo

**👉 [https://1tsprune.github.io/wazgen/](https://1tsprune.github.io/wazgen/)** — langsung akses, no install needed.

### Or run locally

Just open [`index.html`](index.html) in any modern browser. No server required.

```
git clone https://github.com/1tsprune/wazgen.git
cd wazgen
open index.html
```

### Usage

1. **Paste** a log sample or click a quick example button
2. Adjust **Rule ID** and **Level** (auto or manual)
3. Select **MITRE ATT&CK** techniques (optional, multi-select)
4. Click **Generate** — instantly get Rule XML, Decoder XML, ossec.conf, test command
5. **Copy** or **download** the output
6. Deploy to Wazuh: `sudo cp local_rules.xml /var/ossec/etc/rules/ && sudo systemctl restart wazuh-manager`

### Smart Parser

For unknown logs not in the database, WAZGEN's smart parser automatically:

- Detects log format (JSON, syslog, key=value, Windows Event, HTTP access)
- Extracts IP addresses, usernames, ports, and URLs
- Identifies severity keywords (ERROR, FAIL, WARN)
- Generates appropriate decoder and rule with regex pattern
- Shows "Smart Parser" as the source in meta cards

### Batch Processing

Upload a `.log` or `.txt` file with multiple log lines:
- Each line is individually analyzed
- Rules are generated with auto-incrementing IDs
- All rules are combined into a single output
- Max 200 lines per batch

## 🛠️ Tech Stack

| Tech | Purpose |
|---|---|
| **HTML5** | Structure |
| **CSS3** | Styling with CSS custom properties (dark/light mode) |
| **JavaScript** | All logic, no frameworks or dependencies |
| **[Tabler Icons](https://tabler-icons.io)** | UI icons |
| **[Inter](https://rsms.me/inter/) / [JetBrains Mono](https://www.jetbrains.com/lp/mono/)** | Typography |
| **localStorage** | Theme persistence & rule history |
| **FileReader API** | Log file upload & batch processing |
| **Clipboard API** | One-click copy to clipboard |

## 📁 Project Structure

```
wazgen/
├── index.html         # Main HTML (structure only)
├── css/
│   └── style.css      # All styling + dark/light variables
└── js/
    └── app.js         # All logic + 100+ log pattern database
```

## 🌐 Browser Support

| Browser | Support |
|---|---|
| Chrome 60+ | ✅ |
| Firefox 55+ | ✅ |
| Safari 12+ | ✅ |
| Edge 79+ | ✅ |
| Opera 47+ | ✅ |
| Mobile (iOS/Android) | ✅ Responsive with hamburger menu |

## 📜 License

This project is open source. Feel free to use, modify, and distribute.

---

<div align="center">

**Built with ❤️ by [1tsprune](https://1tsprune.com)**  
*Security Engineer & Pentester — Indonesia*

[![GitHub](https://img.shields.io/badge/GitHub-1tsprune-181717?style=flat-square&logo=github)](https://github.com/1tsprune)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Eky_Januarta-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/eky-januarta-aaa3a61aa)

</div>
