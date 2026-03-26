# Splunk Detection Engineering -- SPL Examples
## Wells Fargo Technical Screen Prep

---

## 1. Failed Login Spike (Brute Force / Password Spray)

```splunk
index=security sourcetype=wineventlog EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 10
| sort -count
```

Detects multiple failed logins from a single source within a 5-minute window. Adjust threshold based on baseline. Password spray variant would show low count per user but high count of unique users from one src_ip.

---

## 2. Password Spray Detection (One Source, Many Users)

```splunk
index=security sourcetype=wineventlog EventCode=4625
| bucket _time span=10m
| stats dc(user) as unique_users, count as attempts by _time, src_ip
| where unique_users > 20 AND attempts > 30
| sort -unique_users
```

The key differentiator from brute force -- high unique user count from a single IP is the spray signature.

---

## 3. Successful Login After Multiple Failures (Successful Brute Force)

```splunk
index=security sourcetype=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes by user, src_ip
| where failures > 5 AND successes > 0
| sort -failures
```

Correlates failures followed by success for the same user/IP pair -- a high-fidelity indicator of successful credential attack.

---

## 4. Lateral Movement -- Pass the Hash / Logon Type 3 with NTLM

```splunk
index=security sourcetype=wineventlog EventCode=4624
  Logon_Type=3 Authentication_Package=NTLM
| stats count by user, src_ip, dest, _time
| where count > 5
| sort -count
```

Network logons using NTLM are a classic PtH indicator. Tune by excluding known service accounts and scheduled task sources.

---

## 5. New Local Admin Account Created

```splunk
index=security sourcetype=wineventlog EventCode=4720
| eval is_admin=if(like(Group_Name,"%Administrators%"),1,0)
| join user [search index=security sourcetype=wineventlog EventCode=4732
    | fields user, Group_Name]
| where is_admin=1
| table _time, user, src_user, dest
```

Fires when a new account is created and added to the local Administrators group -- common persistence technique.

---

## 6. Rare Process Execution (Statistical Baselining)

```splunk
index=endpoint sourcetype=sysmon EventCode=1
| stats count by process_name, user, dest
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by process_name
| eval zscore=round((count-avg_count)/stdev_count,2)
| where zscore < -2
| sort zscore
```

Identifies processes executing far below their historical average -- useful for finding LOLBins and rarely-used attacker tools.

---

## 7. PowerShell Encoded Command Execution

```splunk
index=endpoint sourcetype=sysmon EventCode=1
  (process_name=powershell.exe OR process_name=pwsh.exe)
  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-ec *")
| table _time, user, dest, CommandLine, ParentCommandLine
| sort -_time
```

Encoded PowerShell is a staple of living-off-the-land attacks. ParentCommandLine adds context on what spawned it.

---

## 8. LSASS Memory Access (Credential Dumping)

```splunk
index=endpoint sourcetype=sysmon EventCode=10
  TargetImage="*lsass.exe"
| table _time, SourceImage, SourceUser, TargetImage, dest
| sort -_time
```

Sysmon Event 10 captures process access -- LSASS being targeted is a strong Mimikatz/credential dumping indicator. Exclude known AV/EDR processes.

---

## 9. Scheduled Task Creation (Persistence)

```splunk
index=security sourcetype=wineventlog EventCode=4698
| table _time, user, dest, Task_Name, Task_Content
| sort -_time
```

EventCode 4698 fires on scheduled task creation. Attackers commonly use schtasks for persistence. Review Task_Content for suspicious commands or encoded payloads.

---

## 10. Data Exfiltration Indicator -- Large Outbound Transfer

```splunk
index=network sourcetype=firewall action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| eval MB=round(total_bytes/1024/1024,2)
| where MB > 500
| sort -MB
```

Flags endpoints sending large volumes outbound. Tune threshold based on environment baseline. Correlate dest_ip against threat intel feeds for context.

---

## Interview Discussion Points

- How to tune each query to reduce false positive rate (90% FP reduction via automation and tuning)
- How to promote detections from development to production in a detection-as-code pipeline
- MITRE ATT&CK technique mapping per query:
  - Queries 1-3: T1110 Brute Force / T1586 Compromise Accounts
  - Query 4: T1550.002 Pass the Hash
  - Query 5: T1136.001 Create Local Account
  - Query 6: T1218 Signed Binary Proxy Execution / LOLBins broadly
  - Query 7: T1059.001 PowerShell
  - Query 8: T1003.001 LSASS Memory
  - Query 9: T1053.005 Scheduled Task
  - Query 10: T1048 Exfiltration Over Alternative Protocol
