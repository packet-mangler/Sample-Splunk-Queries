# Splunk Threat Hunting -- SPL Examples
## Wells Fargo Technical Screen Prep

---

## 1. Baseline Deviation -- Off-Hours Authentication

```splunk
index=security sourcetype=wineventlog EventCode=4624
| eval hour=strftime(_time,"%H")
| eval off_hours=if(hour<6 OR hour>20,"YES","NO")
| where off_hours="YES"
| stats count by user, src_ip, dest, hour
| sort -count
```

Hunters start with time -- legitimate users have predictable patterns. Authentication outside business hours, especially for privileged accounts, warrants investigation.

---

## 2. Hunt for Living Off the Land Binaries (LOLBins)

```splunk
index=endpoint sourcetype=sysmon EventCode=1
| eval lolbin=if(match(process_name,
    "(?i)(certutil|mshta|wscript|cscript|regsvr32|rundll32|msiexec|bitsadmin|wmic|forfiles|pcalua|odbcconf)"),
    "YES","NO")
| where lolbin="YES"
| table _time, user, dest, process_name, CommandLine, ParentCommandLine
| sort -_time
```

LOLBins are legitimate Windows tools abused by attackers to blend in. Certutil downloading files, mshta executing remote scripts, and regsvr32 loading DLLs are classic abuse patterns.

---

## 3. Parent-Child Process Anomaly -- Office Apps Spawning Shells

```splunk
index=endpoint sourcetype=sysmon EventCode=1
| where match(ParentImage,"(?i)(winword|excel|powerpnt|outlook|onenote)")
  AND match(process_name,"(?i)(cmd|powershell|wscript|cscript|mshta|rundll32)")
| table _time, user, dest, ParentImage, process_name, CommandLine
| sort -_time
```

Office applications should never spawn command shells under normal circumstances. This is a high-fidelity macro-based malware and phishing indicator.

---

## 4. Hunt for Reconnaissance Activity -- Net Commands

```splunk
index=endpoint sourcetype=sysmon EventCode=1
  process_name="net.exe" OR process_name="net1.exe"
| eval recon=if(match(CommandLine,
    "(?i)(user|group|localgroup|view|share|session|accounts|config)"),
    "YES","NO")
| where recon="YES"
| stats count by user, dest, CommandLine
| sort -count
```

net.exe enumeration commands are standard attacker reconnaissance. High volume or unusual timing on these commands in your environment is worth investigating.

---

## 5. Hunt for Abnormal Volume of DNS Requests Per Host

```splunk
index=network sourcetype=dns
| bucket _time span=1h
| stats count as dns_requests by _time, src_ip
| eventstats avg(dns_requests) as avg_req, stdev(dns_requests) as stdev_req by src_ip
| eval zscore=round((dns_requests-avg_req)/stdev_req,2)
| where zscore > 3
| sort -zscore
```

Hosts making abnormally high DNS requests relative to their own baseline may be beaconing, running DNS tunneling, or running DGA-based malware.

---

## 6. Hunt for Domain Generation Algorithm (DGA) Activity

```splunk
index=network sourcetype=dns
| eval domain_length=len(query)
| eval consonant_ratio=round(
    (len(replace(query,"[aeiouAEIOU]",""))/domain_length),2)
| where domain_length > 12 AND consonant_ratio > 0.7
| stats count by src_ip, query, consonant_ratio
| sort -consonant_ratio
```

DGA domains tend to be long and have high consonant-to-vowel ratios compared to legitimate domain names. This is a heuristic hunt -- high false positives expected, tune against known-good domain lists.

---

## 7. Hunt for Credential Access -- Security Log Cleared

```splunk
index=security sourcetype=wineventlog
  (EventCode=1102 OR EventCode=104)
| table _time, user, dest, EventCode
| sort -_time
```

EventCode 1102 (Security log cleared) and 104 (System log cleared) are strong indicators of an attacker covering tracks post-compromise. Should be near-zero in a healthy environment.

---

## 8. Hunt for Unusual Service Installation

```splunk
index=security sourcetype=wineventlog EventCode=7045
| table _time, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, dest
| sort -_time
```

New service installation (EventCode 7045) is a common persistence mechanism. Hunt for services with random names, services pointing to temp directories, or services running from unusual paths.

---

## 9. Hunt for Internal Port Scanning

```splunk
index=network sourcetype=firewall action=allowed
| stats dc(dest_port) as unique_ports, count as connections by src_ip, dest_ip
| where unique_ports > 20
| sort -unique_ports
```

A single internal host connecting to many destination ports on another host is a classic port scan signature. Tune threshold based on environment -- exclude known vulnerability scanners.

---

## 10. Hunt for Impossible Travel -- Same User, Multiple Geolocations

```splunk
index=security sourcetype=wineventlog EventCode=4624
| iplocation src_ip
| stats values(Country) as countries, dc(Country) as country_count,
        values(src_ip) as src_ips by user
| where country_count > 1
| sort -country_count
```

Same user authenticating from multiple countries within a short timeframe is a strong account compromise indicator. Requires GeoIP lookup data in Splunk. Particularly relevant for Wells Fargo given their global footprint.

---

## Interview Discussion Points

- How you form a hunt hypothesis before writing the query -- hypothesis-driven hunting vs. IOC-based hunting
- How you document hunt results regardless of outcome -- negative results are still valuable
- How you operationalize a successful hunt into a permanent detection rule
- How you prioritize hunts based on threat intelligence -- mapping current threat actor TTPs to your environment
- The difference between a hunt and a scheduled alert -- and when each is appropriate
- MITRE ATT&CK technique mapping per query:
  - Query 1: T1078 Valid Accounts / T1133 External Remote Services
  - Query 2: T1218 Signed Binary Proxy Execution / T1105 Ingress Tool Transfer
  - Query 3: T1566.001 Spearphishing Attachment / T1059 Command and Scripting Interpreter
  - Query 4: T1087 Account Discovery / T1135 Network Share Discovery
  - Query 5: T1071.004 DNS / T1568 Dynamic Resolution
  - Query 6: T1568.002 Domain Generation Algorithms
  - Query 7: T1070.001 Clear Windows Event Logs
  - Query 8: T1543.003 Windows Service
  - Query 9: T1046 Network Service Discovery
  - Query 10: T1078 Valid Accounts / T1534 Internal Spearphishing (follow-on)
