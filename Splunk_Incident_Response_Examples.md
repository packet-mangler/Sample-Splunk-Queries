# Splunk Incident Response -- SPL Examples
## Wells Fargo Technical Screen Prep

---

## 1. Identify All Activity from a Suspicious IP

```splunk
index=* src_ip="10.10.10.100"
| stats count by index, sourcetype, _time, user, dest, action
| sort -_time
```

First-response query when an IP is flagged. Casts wide net across all indexes to build a full picture of what that IP touched.

---

## 2. Account Compromise -- All Activity for a Suspicious User

```splunk
index=* (user="jsmith" OR src_user="jsmith")
| stats count by index, sourcetype, action, dest, src_ip
| sort -_time
```

Scope the blast radius of a potentially compromised account. Look for unusual src_ip values, off-hours activity, and access to systems outside normal behavior.

---

## 3. Timeline Reconstruction for a Specific Host

```splunk
index=* dest="WORKSTATION01" OR src="WORKSTATION01"
| eval direction=if(dest="WORKSTATION01","inbound","outbound")
| table _time, direction, src_ip, dest, user, action, sourcetype
| sort _time
```

Builds a chronological event timeline for a specific host during an IR investigation. Essential for establishing attack sequence.

---

## 4. Detect Ransomware Indicators -- Mass File Rename/Extension Change

```splunk
index=endpoint sourcetype=sysmon EventCode=11
| rex field=TargetFilename "\.(?<extension>[^.]+)$"
| stats count by extension, dest, user
| where count > 100
| sort -count
```

Sysmon Event 11 captures file creation events. Mass creation of files with unusual extensions is a ransomware staging indicator. Tune extension list against known ransomware extensions.

---

## 5. C2 Beacon Detection -- Periodic Outbound Connections

```splunk
index=network sourcetype=firewall action=allowed direction=outbound
| bucket _time span=1h
| stats count by _time, src_ip, dest_ip, dest_port
| eventstats stdev(count) as stdev, avg(count) as avg by src_ip, dest_ip
| eval regularity=round(stdev/avg,2)
| where regularity < 0.2 AND count > 10
| sort regularity
```

Low standard deviation relative to average connection count indicates beaconing behavior -- highly periodic traffic is a C2 hallmark.

---

## 6. DNS Exfiltration Detection -- Unusually Long DNS Queries

```splunk
index=network sourcetype=dns
| eval query_length=len(query)
| where query_length > 50
| stats count, avg(query_length) as avg_len by src_ip, dest_ip
| sort -avg_len
```

DNS tunneling typically produces abnormally long subdomains. Flag queries exceeding normal length thresholds and correlate src_ip against endpoint data.

---

## 7. Privileged Account Used from New Location

```splunk
index=security sourcetype=wineventlog EventCode=4624
  (user="*admin*" OR user="*svc*")
| stats dc(src_ip) as unique_src, values(src_ip) as src_ips by user
| where unique_src > 3
| sort -unique_src
```

Privileged accounts authenticating from multiple source IPs -- especially new ones -- is a strong lateral movement or credential theft indicator.

---

## 8. Detect Use of Known Attack Tools by Process Name

```splunk
index=endpoint sourcetype=sysmon EventCode=1
| eval suspicious=if(match(process_name,
    "(?i)(mimikatz|psexec|wce|pwdump|cobalt|beacon|meterpreter|netcat|nc\.exe|nmap)"),
    "YES","NO")
| where suspicious="YES"
| table _time, user, dest, process_name, CommandLine, ParentCommandLine
| sort -_time
```

Pattern match against a list of known offensive tool names. Expand the regex list based on your threat intelligence.

---

## 9. Containment Verification -- Confirm Host is No Longer Communicating

```splunk
index=network sourcetype=firewall
  (src_ip="10.10.10.100" OR dest_ip="10.10.10.100")
  earliest=-1h latest=now
| stats count by action, src_ip, dest_ip
```

Post-containment check to confirm an isolated host has no active network connections. Run repeatedly during IR to verify containment is holding.

---

## 10. Post-Incident -- User Account Activity Summary for Executive Briefing

```splunk
index=security sourcetype=wineventlog
  (EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4720 OR EventCode=4728)
  user="jsmith"
| eval event_type=case(
    EventCode=4624, "Successful Login",
    EventCode=4625, "Failed Login",
    EventCode=4648, "Explicit Credential Use",
    EventCode=4720, "Account Created",
    EventCode=4728, "Added to Security Group")
| stats count by event_type, src_ip, dest
| sort -count
```

Produces a clean summary of all security-relevant activity for a specific user -- formatted for inclusion in an executive IR briefing or regulatory report. Directly relevant to Wells Fargo's audit and compliance context.

---

## Interview Discussion Points

- How you triage and prioritize these queries during an active incident
- How you translate query output into IR playbook steps
- How you document findings for audit and regulatory evidence -- directly relevant to Wells Fargo's OCC oversight environment
- How you use SOAR to automate repetitive queries (containment verification, scope queries) so analysts focus on analysis
- MITRE ATT&CK technique mapping per query:
  - Query 1-2: T1078 Valid Accounts / T1133 External Remote Services
  - Query 3: General investigation -- supports T1021 Remote Services
  - Query 4: T1486 Data Encrypted for Impact (Ransomware)
  - Query 5: T1071 Application Layer Protocol / T1132 Data Encoding (C2)
  - Query 6: T1048.001 Exfiltration Over DNS
  - Query 7: T1078.002 Domain Accounts / T1550 Use Alternate Auth Material
  - Query 8: T1588.002 Tool acquisition / multiple execution techniques
  - Query 9: Containment verification -- supports IR process, not a specific TTP
  - Query 10: Post-incident documentation -- supports audit and regulatory evidence
