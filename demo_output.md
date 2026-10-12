# 🛡️ SENTINEL Multi-Agent Investigation Demo Output

## 📧 Email / Phishing Analyst Findings
**Summary:**

This email is a phishing attack using social engineering tactics to create a sense of urgency and spoofing the sender's email to appear as a legitimate Microsoft support alert. The email has failed SPF and DKIM authentication, indicating that the sender's email address is likely spoofed. The malicious payload is a URL that leads to an attacker-controlled server, likely for password capture or malware installation.

**Detailed Findings:**

1. **Social Engineering Tactics:**
	* Urgency: The email creates a sense of urgency by claiming the recipient's Office365 account is compromised, which is a common tactic to prompt the recipient into taking immediate action.
	* Spoofing: The sender's email address appears to be a legitimate Microsoft support alert, but the IP address 192.168.1.100 is not a valid Microsoft IP address, indicating spoofing.
2. **Header Anomalies:**
	* Failed SPF: The email failed SPF authentication, which suggests that the sender's email address is spoofed.
	* Failed DKIM: The email failed DKIM authentication, which indicates that the sender's email is likely tampered with or forged.
3. **Malicious Payload:**
	* Suspicious URL: The URL found in the email body, http://evil-c2-server.com/login, leads to an attacker-controlled server, likely for password capture or malware installation.

## 💻 Endpoint Analyst Findings
Based on the provided Windows event logs and Sigma matches, the following potential threats are identified:

1. **Potential Execution**:
	* **T1037.003 - Network Logon Script**: A network logon script was executed at 11:06:29, indicating potential persistence.
	* **Process execution**: Multiple instances of cmd.exe, conhost.exe, and dllhost.exe were executed at 11:06:29 and 11:06:46, which could be indicative of malware execution.
2. **Persistence**:
	* **T1037.003 - Network Logon Script**: The execution of a network logon script suggests potential persistence mechanisms.
3. **Privilege Escalation**:
	* **Process execution**: The execution of dllhost.exe at 11:06:46 might indicate an attempt to escalate privileges, as dllhost.exe is a component of the Windows operating system that can be used to launch processes with elevated privileges.

It is essential to investigate further to confirm these findings and determine the full scope of the threat.

## 🌐 Network Analyst Findings
**Anomalous Activity Detected:**

* **Initial C2 Beacon:** The attacker made a DNS query to `evil-c2-server.com` at 15:33:25, indicating an initial C2 beacon attempt.
* **Covert C2 Beacon:** The encoded DNS tunnel query at 15:33:30 (`dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org`) suggests a covert C2 beacon attempt using a DNS tunnel.
* **Lateral Movement:** No evidence of lateral movement was found in the provided logs.

**Exfiltration:**

* **Data Exfiltration:** A POST request was made to `10.10.10.50` at 15:37:30 (`/upload/credentials.zip`), indicating potential data exfiltration.

**Recommendations:**

* Investigate the DNS tunnel query and encoded payload for further analysis.
* Monitor the C2 beacon attempts and investigate the potential data exfiltration.
* Review the network traffic and system logs for any additional signs of suspicious activity.

## 🧠 Memory Analyst Findings
No memory artifacts provided.

## 📊 Incident Timeline & Narrative
**Incident Timeline:**

**Time**: 15:33:25 - 15:37:30

**Chronological Events:**

1. **Initial C2 Beacon** (15:33:25):
	* The attacker made a DNS query to `evil-c2-server.com`, indicating an initial C2 beacon attempt.
2. **Covert C2 Beacon** (15:33:30):
	* The encoded DNS tunnel query at `dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org` suggests a covert C2 beacon attempt using a DNS tunnel.
3. **Process Execution** (15:33:30 - 15:37:30):
	* Multiple instances of cmd.exe, conhost.exe, and dllhost.exe were executed, which could be indicative of malware execution.
	* The execution of dllhost.exe at 15:36:46 might indicate an attempt to escalate privileges.
4. **Data Exfiltration** (15:37:30):
	* A POST request was made to `10.10.10.50` (`/upload/credentials.zip`), indicating potential data exfiltration.

**Possible Attack Sequence:**

1. The attacker sent a phishing email (15:30:00 - 15:33:25) to create a sense of urgency and prompt the recipient into taking immediate action.
2. The recipient, under the assumption that the email is legitimate, clicked on the malicious URL, leading to the execution of malware and the establishment of a C2 beacon (15:33:25).
3. The attacker then used the C2 beacon to execute additional malicious processes (15:33:30 - 15:37:30), potentially escalating privileges and establishing persistence.
4. The attacker then exfiltrated sensitive data (15:37:30) by uploading the `credentials.zip` file to `10.10.10.50`.

**Recommendations:**

* Investigate the DNS tunnel query and encoded payload for further analysis.
* Monitor the C2 beacon attempts and investigate the potential data exfiltration.
* Review the network traffic and system logs for any additional signs of suspicious activity.
* Review email logs for similar phishing attempts and take measures to block spoofed emails.
* Update security protocols to include monitoring for DNS tunnel queries and encoded payloads.

## 🔍 Threat Hunting Queries (Splunk SPL / KQL / EQL)
### Splunk SPL Query
```sql
index=* 
("evil-c2-server.com" OR "10.10.10.50" OR "::1" OR "http://evil-c2-server.com/login" OR "dc01.corp.local" OR "dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org") 
("cmd.exe" OR "conhost.exe" OR "dllhost.exe") 
("POST /upload/credentials.zip" OR "GET /login")
```
This query searches across all indexes for the identified IOCs, malicious process executions, and potential data exfiltration indicators.

### Microsoft Sentinel / Azure KQL Query
```kql
DeviceProcessEvents
| where ProcessName == "cmd.exe" or ProcessName == "conhost.exe" or ProcessName == "dllhost.exe"
| where Computer == "dc01.corp.local"
| union (DeviceNetworkEvents
| where DestinationAddress == "10.10.10.50" or DestinationAddress == "::1")
```
This query hunts for the identified malicious process executions and network connections related to the threat.

### Elastic (EQL) Query
```sql
process where process_name = "cmd.exe" or process_name = "conhost.exe" or process_name = "dllhost.exe"
| has (network.direction = "inbound" and network.ip = "10.10.10.50")
| has (dns.query_name = "evil-c2-server.com" or dns.query_name = "dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org")
```
This query searches for lateral movement or persistence tied to the identified threat, focusing on DNS tunnel queries and encoded payloads.

## 🛡️ SOAR Remediation Plan
**Remediation Plan**
=====================

### Network Containment
------------------------

#### Block Malicious IPs/Domains

**Firewall Commands:**

* **Windows:**
```bash
netsh advfirewall set global state=on
netsh advfirewall firewall add rule dir=in action=block protocol=udp localport=53 remoteip=10.10.10.50
netsh advfirewall firewall add rule dir=in action=block protocol=tcp remoteip=evil-c2-server.com
```

* **Linux:**
```bash
iptables -A INPUT -s 10.10.10.50 -j DROP
iptables -A INPUT -p udp --dport 53 -j DROP
iptables -A INPUT -p tcp -d evil-c2-server.com -j DROP
```

### Endpoint Isolation
------------------------

#### Isolate Compromised Hosts

**EDR Commands:**

* **CrowdStrike Falcon:**
```bash
curl -X POST \
  https://crowdstrike.com/api/v1/hosts/ \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{"hostname": "dc01.corp.local", "isolation": "true"}'
```

* **Microsoft Defender API:**
```bash
curl -X POST \
  https://graph.microsoft.com/v1.0/deviceManagement/devices/dc01.corp.local/isolateDevice \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"isolationReason": "Suspicious activity detected"}'
```

### Custom Detection Rule
---------------------------

#### Sigma Rule
```yml
title: DNS Tunnels and Encoded Payloads
description: Detects DNS tunnel queries and encoded payloads
id: dns-tunnel-enc
type: detection
logsource:
  category: dns
  product: windows
detection:
  selection:
    query: dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org
    event_id: 4005
    process_name: dns.exe
  condition: selection
  timewindow: 5m
falsepositives:
  - Legitimate DNS queries
data_to_collect:
  - query
  - event_id
  - process_name
  - timestamp
```

#### YARA Rule
```yara
rule DNS_Tunnels_and_Encoded_Payloads
{
    meta:
        author = "Your Name"
        description = "Detects DNS tunnel queries and encoded payloads"
        date = "2023-02-20"
    strings:
        $dns_tunnel = "dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ" at 0
    condition:
        all of them
}
```
Note: The above YARA rule is just an example and may require modifications to fit your specific use case.

## 🎫 Automated SOC Ticket (Jira / ServiceNow API)
```json
{
    "fields": {
        "project": {"key": "SOC"},
        "summary": "CRITICAL INCIDENT: Malware Execution and Data Exfiltration",
        "description": "Incident Timeline:\n\n**Time**: 15:33:25 - 15:37:30\n\n**Chronological Events:\"\n\n1. **Initial C2 Beacon** (15:33:25):\n\n* The attacker made a DNS query to `evil-c2-server.com`, indicating an initial C2 beacon attempt.\n\n2. **Covert C2 Beacon** (15:33:30):\n\n* The encoded DNS tunnel query at `dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org` suggests a covert C2 beacon attempt using a DNS tunnel.\n\n3. **Process Execution** (15:33:30 - 15:37:30):\n\n* Multiple instances of cmd.exe, conhost.exe, and dllhost.exe were executed, which could be indicative of malware execution.\n\n* The execution of dllhost.exe at 15:36:46 might indicate an attempt to escalate privileges.\n\n4. **Data Exfiltration** (15:37:30):\n\n* A POST request was made to `10.10.10.50` (`/upload/credentials.zip`), indicating potential data exfiltration.\n\n**Possible Attack Sequence:\"\n\n1. The attacker sent a phishing email (15:30:00 - 15:33:25) to create a sense of urgency and prompt the recipient into taking immediate action.\n\n2. The recipient, under the assumption that the email is legitimate, clicked on the malicious URL, leading to the execution of malware and the establishment of a C2 beacon (15:33:25).\n\n3. The attacker then used the C2 beacon to execute additional malicious processes (15:33:30 - 15:37:30), potentially escalating privileges and establishing persistence.\n\n4. The attacker then exfiltrated sensitive data (15:37:30) by uploading the `credentials.zip` file to `10.10.10.50`.\n\n**Recommendations:\"\n\n* Investigate the DNS tunnel query and encoded payload for further analysis.\n\n* Monitor the C2 beacon attempts and investigate the potential data exfiltration.\n\n* Review the network traffic and system logs for any additional signs of suspicious activity.\n\n* Review email logs for similar phishing attempts and take measures to block spoofed emails.\n\n* Update security protocols to include monitoring for DNS tunnel queries and encoded payloads.\n\n**Remediation Plan:\"\n\n### Network Containment\n\n#### Block Malicious IPs/Domains\n\n**Firewall Commands:\"\n\n* **Windows:\"\n\nnetsh advfirewall set global state=on\n\nnetsh advfirewall firewall add rule dir=in action=block protocol=udp localport=53 remoteip=10.10.10.50\n\nnetsh advfirewall firewall add rule dir=in action=block protocol=tcp remoteip=evil-c2-server.com\n\n* **Linux:\"\n\niptables -A INPUT -s 10.10.10.50 -j DROP\n\niptables -A INPUT -p udp --dport 53 -j DROP\n\niptables -A INPUT -p tcp -d evil-c2-server.com -j DROP\n\n### Endpoint Isolation\n\n#### Isolate Compromised Hosts\n\n**EDR Commands:\"\n\n* **CrowdStrike Falcon:\"\n\ncurl -X POST \\n  https://crowdstrike.com/api/v1/hosts/ \\n  -H 'Content-Type: application/json' \\n  -H 'Authorization: Bearer YOUR_API_KEY' \\n  -d '{"hostname": "dc01.corp.local", "isolation": "true"}'\n\n* **Microsoft Defender API:\"\n\ncurl -X POST \\n  https://graph.microsoft.com/v1.0/deviceManagement/devices/dc01.corp.local/isolateDevice \\n  -H 'Authorization: Bearer YOUR_API_KEY' \\n  -H 'Content-Type: application/json' \\n  -d '{"isolationReason": "Suspicious activity detected"}'\n\n### Custom Detection Rule\n\n#### Sigma Rule\"\n\ntitle: DNS Tunnels and Encoded Payloads\n\ndescription: Detects DNS tunnel queries and encoded payloads\n\nid: dns-tunnel-enc\n\ntype: detection\n\nlogsource:\n  category: dns\n  product: windows\n\ndetection:\n  selection:\n    query: dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ.tunnel.attacker-network.org\n    event_id: 4005\n    process_name: dns.exe\n  condition: selection\n  timewindow: 5m\nfalsepositives:\n  - Legitimate DNS queries\n\ndata_to_collect:\n  - query\n  - event_id\n  - process_name\n  - timestamp\n\n#### YARA Rule\"\n\trule DNS_Tunnels_and_Encoded_Payloads\n{\n    meta:\n        author = \"Your Name\"\n        description = \"Detects DNS tunnel queries and encoded payloads\"\n        date = \"2023-02-20\"\n    strings:\n        $dns_tunnel = \"dGhpc2lzYW1hbGljaW91c2V4ZmlsdHJhdGlvbnR1bm5lbHBheWxvYWQ\" at 0\n    condition:\n        all of them\n}",
        "issuetype": {"name": "Incident"},
        "priority": {"name": "Highest"},
        "customfield_1001": "Block malicious IPs/domains, isolate compromised hosts, investigate DNS tunnel query and encoded payload, monitor C2 beacon attempts and potential data exfiltration"
    }
}
```
