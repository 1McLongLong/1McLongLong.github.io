---
title: Getting Started with Web Development
layout: page
permalink: /blogs/blog1
---

**Noxious - LLMNR Poisoning Investigation**

This writeup documents a network forensics investigation of an LLMNR
Poisoning attack in an Active Directory environment. The investigation
involved analyzing packet capture (PCAP) data to identify a rogue
device, extract compromised credentials, and understand the complete
attack chain from initial compromise to password cracking.

Table of Contents

1.  Prerequisites

2.  Core Concepts

3.  Tools Required

4.  Attack Overview

5.  Investigation Questions & Analysis

6.  Key Findings

7.  Lessons Learned

1\. Prerequisites

1.1 Knowledge Requirements

-  Basic networking fundamentals (IP addresses, protocols, ports)

-  Understanding of TCP/IP communication

-  Familiarity with Wireshark interface and basic filtering

-  Basic understanding of Windows networking concepts

1.2 Skills Required

-   Packet capture analysis

-   Display filter creation in Wireshark

-   Basic command-line usage

-   Understanding of hash formats and password cracking concepts

2\. Core Concepts

2.1 Active Directory Environment

Active Directory (AD) is Microsoft\'s centralized network management
system. Think of it as a kingdom where:

-   Domain Controller (DC) - The castle/central authority that manages
    authentication, user accounts, and permissions

-   Workstations - Individual computers (citizens) that request access
    to resources

-   File Shares - Network folders accessible to authenticated users

2.2 Name Resolution in Windows

When you type a server name like \\\\FileServer, Windows needs to
convert this name into an IP address. This process follows a specific
order:

-   DNS (Domain Name System) - Primary method, queries the Domain
    Controller

-   LLMNR (Link-Local Multicast Name Resolution) - Fallback method when
    DNS fails

-   NetBIOS - Older legacy fallback method

2.3 LLMNR (Link-Local Multicast Name Resolution)

LLMNR is a protocol that allows computers to resolve hostnames without
requiring a DNS server. Key characteristics:

-   Uses UDP port 5355

-   Broadcasts queries to the entire network segment (multicast address
    224.0.0.252)

-   Any machine can respond to LLMNR queries - this is the
    vulnerability!

-   Often triggers on typos or when accessing non-existent shares

2.4 NTLM Authentication

NTLM (NT LAN Manager) is Windows\' authentication protocol. It uses a
3-way handshake:

-   NEGOTIATE - Client initiates connection

-   CHALLENGE - Server sends a random challenge value

-   AUTH - Client responds with encrypted hash using their password +
    challenge

**Critical Point:** Windows automatically sends authentication
credentials when connecting to SMB shares. This happens without user
interaction!

2.5 Hash Components (NTLMv2)

To crack an NTLMv2 hash, we need to extract and combine several values:

-   Username - The account being authenticated

-   Domain - The Active Directory domain

-   Server Challenge - Random value from CHALLENGE packet

-   NTProofStr - First 16 bytes of NTLMv2 Response

-   NTLMv2 Response - Full encrypted response (minus first 16 bytes for
    hash format)

3\. Tools Required

3.1 Analysis Tools

-   Wireshark - Network protocol analyzer for PCAP analysis

-   Hashcat - Password recovery tool for cracking NTLMv2 hashes

-   Text editor - For creating hash files

3.2 Required Resources

-   rockyou.txt wordlist - Common password dictionary for hash cracking

4\. The LLMNR Poisoning Attack

4.1 Attack Flow

The attack follows this sequence:

-   Victim makes a typo when accessing a network share (e.g., \\\\DCC01
    instead of \\\\DC01)

-   DNS resolution fails because DCC01 doesn\'t exist

-   Windows falls back to LLMNR and broadcasts: \'Does anyone know
    DCC01?\'

-   Attacker\'s machine (running Responder tool) responds: \'Yes! I\'m
    DCC01 at 172.17.79.135\'

-   Victim connects to attacker\'s machine thinking it\'s the legitimate
    server

-   Windows automatically sends NTLM authentication (username + hash)

-   Attacker captures the NTLMv2 hash

-   Attacker uses Hashcat to crack the hash offline and recover the
    password

4.2 Why This Attack Works

-   LLMNR is enabled by default in Windows environments

-   Any device can respond to LLMNR queries - no authentication required

-   Windows automatically sends credentials when connecting to SMB
    shares

-   Users commonly make typos when typing server names

-   The attack is passive - difficult to detect without proper
    monitoring

5\. Investigation: Questions & Analysis

Question 1: Identify the Malicious IP Address

**Objective:** Find the IP address of the rogue machine running the Responder tool.

**Methodology:**

-   Enable Name Resolution in Wireshark (View → Name Resolution → Enable
    all options)

-   Filter for DNS traffic to identify the legitimate Domain Controller

-   Apply filter: llmnr && ip (to see only IPv4 LLMNR traffic)

-   Identify who is responding to LLMNR queries

**Key Finding:**

-   Legitimate Domain Controller: 172.17.79.4 (DC01)

-   Victim machine: 172.17.79.136 (Forela-Wkstn002)

-   Rogue machine responding to LLMNR: 172.17.79.135

**Answer: 172.17.79.135**

Question 2: What is the hostname of the rogue machine?

**Objective:** Determine the actual hostname of the attacker\'s machine.

**Methodology:**

-   Apply filter: ip.addr == 172.17.79.135 && dhcp

-   Look for DHCP Request or DHCP Discover packets

-   Expand Bootstrap Protocol → Option: (12) Host Name

**Answer: kali**

Question 3: What is the username whose hash was captured?

**Objective:** Determine which user\'s credentials were captured.

**Methodology:**

-   Apply filter: ntlmssp

-   Look for NTLMSSP_AUTH packets

-   Examine the username field in the authentication data

**Alternative filter:** ntlmssp.auth.username

**Answer: john.deacon**

Question 4: When were the hashes captured the First time?

**Objective:** Find when the credentials were first captured.

**Methodology:**

-   Change time display: View → Time Display Format → UTC Date and Time
    of Day

-   Filter: ntlmssp

-   Identify the FIRST set of three packets (NEGOTIATE, CHALLENGE, AUTH)

-   Note the timestamp of the NTLMSSP_AUTH packet

**Key Observation:**

Multiple NTLM negotiations occur in quick succession as the victim\'s machine repeatedly attempts to authenticate.

**Answer: 2024-06-24 11:18:30**

Question 5: What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?

**Objective:** Determine what the victim mistyped that triggered the attack.

**Methodology:**

-   Review LLMNR traffic from earlier analysis

-   Examine the queried hostname in LLMNR requests

-   Compare with known Domain Controller name (DC01)

**Key Finding:**

The victim typed DCC01 instead of DC01 - a simple one-character typo that enabled the entire attack.

**Answer: DCC01**

Question 6: What is the NTLM server challenge value?

**Objective:** Extract the server challenge value needed for hash cracking.

**Methodology:**

-   Filter: ntlmssp

-   Focus on the FIRST NTLMSSP_CHALLENGE packet

**Answer: 601019d191f054f1**

Question 7: What is the NTProofStr value?

**Objective:** Extract the NTProofStr value from the authentication response.

**Methodology:**

-   Locate the NTLMSSP_AUTH packet (third in the first set)

**Answer: c0cc803a6d9fb5a9082253a04dbd4cd4**

Question 8: Crack the Password

**Objective:** Reconstruct the NTLMv2 hash and crack it to recover the plaintext password.

**Methodology:**

-   Extract the full NTLMv2 Response (found above NTProofStr in the same
    location)

-   Remove the first 32 characters (first 16 bytes) from NTLMv2 Response

-   Construct hash in format:
    username::domain:challenge:ntproofstr:response

-   Save to hash.txt file

-   Run Hashcat: hashcat -a 0 -m 5600 hash.txt rockyou.txt

**Hash Format:**

john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:0101000000...

**Hashcat Command Breakdown:**

-   -a 0: Dictionary attack mode

-   -m 5600: NTLMv2 hash type

-   hash.txt: File containing the hash

-   rockyou.txt: Password wordlist

**Answer: NotMyPassword0k?** (The Hashcat result shows the password with a small k, HTB accepts the password anyway but i don't know who's in the wrong.)

Question 9: What is the actual file share that the victim was trying to navigate to?

**Objective:** Determine what file share the victim was actually trying to access.

**Methodology:**

-   Filter: smb2.tree

-   Look for Tree Connect Request packets

-   Find connections to the CORRECT DC (DC01, not DCC01)

-   Identify non-default shares (exclude IPC\$, ADMIN\$, etc.)

**Answer: \\\\DC01\\DC-Confidential**

6\. Key Findings Summary

6.1 Attack Timeline

Complete attack sequence occurred:

-   User john.deacon typed \\\\DCC01 instead of \\\\DC01

-   LLMNR query broadcast to network

-   Attacker (172.17.79.135 / kali) responded

-   NTLMv2 hash captured

-   User successfully connected to correct share

6.2 Network Indicators

  ----------------------------------- -----------------------------------
  **Indicator**                       **Value**

  Attacker IP                         172.17.79.135

  Attacker Hostname                   kali

  Victim IP                           172.17.79.136

  Victim Hostname                     Forela-Wkstn002

  Domain Controller                   172.17.79.4 (DC01)

  Compromised User                    john.deacon

  Domain                              FORELA

  Typo Made                           DCC01

  Intended Target                     \\\\DC01\\DC-Confidential

  Password                            NotMyPassword0K?
  ----------------------------------- -----------------------------------

6.3 Protocols Observed

-   LLMNR (UDP 5355) - Attack vector

-   SMB2 - File sharing protocol

-   NTLMSSP - Authentication protocol

-   DHCP - Network configuration (revealed attacker hostname)

-   DNS - Normal name resolution (for comparison)

7\. Lessons Learned

7.1 Technical Insights

-   LLMNR is a significant security risk in Active Directory
    environments

-   Simple typos can lead to credential theft

-   Windows automatically sends credentials to SMB shares without user
    interaction

-   Captured hashes can be cracked offline - password complexity is
    crucial

-   Multiple authentication attempts occur in rapid succession

7.2 Investigation Techniques

-   Start with identifying legitimate infrastructure (DC) before hunting
    for anomalies

-   DHCP traffic reveals true hostnames (attacker can\'t easily spoof)

-   Timestamps help correlate related events across different protocols

-   Focus on the FIRST occurrence when multiple similar events exist

-   Understanding protocol structure is essential for extracting hash
    components

8\. Conclusion

This investigation successfully identified and analyzed an LLMNR
Poisoning attack in an Active Directory environment. Through systematic
packet analysis, we traced the complete attack chain from initial typo
to password compromise. The investigation demonstrated that a
single-character typing error combined with insecure default protocols
can lead to credential theft.

Key takeaways include the importance of disabling legacy protocols like
LLMNR, implementing strong password policies, and maintaining robust
network monitoring. The ability to extract and crack NTLMv2 hashes from
network traffic highlights why defense-in-depth strategies are essential
in modern enterprise networks.

This analysis reinforces that network security requires both technical
controls (disabling LLMNR, SMB signing) and user awareness (recognizing
typos, understanding authentication risks). Organizations must assume
breach and implement monitoring capabilities to detect such attacks in
progress.


9\. References & Resources

9.1 Tools Documentation

-   Hashcat Documentation: https://hashcat.net/wiki/

-   Responder Tool: https://github.com/lgandx/Responder

9.2 Protocol References

-   RFC 4795 - Link-Local Multicast Name Resolution (LLMNR)

-   Microsoft NTLM Documentation

-   SMB2/3 Protocol Specifications

9.3 Additional Learning Resources

-   MITRE ATT&CK T1557.001 - LLMNR/NBT-NS Poisoning

-   Active Directory Security Best Practices



[← Back to Blogs](/myblogs)
