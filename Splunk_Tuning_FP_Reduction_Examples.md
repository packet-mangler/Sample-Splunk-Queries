# Splunk Tuning and False Positive Reduction -- SPL Examples
## Wells Fargo Technical Screen Prep

---

## 1. Identify Top False Positive Contributors in Notable Events

```splunk
index=notable
| stats count by rule_name, src_ip, user, dest
| sort -count
| head 20
```

Start here when attacking FP volume. The top 20 rule/source combinations are almost always responsible for the majority of noise. This is the foundation of your 90% FP reduction story.

---

## 2. Suppress Known-Good Sources with a Lookup

```splunk
index=security sourcetype=wineventlog EventCode=4625
| lookup known_good_ips src_ip OUTPUT is_known_good
| where isnull(is_known_good) OR is_known_good!="YES"
| stats count by src_ip, user, dest
| sort -count
```

Maintain a lookup table (known_good_ips.csv) of sanctioned scanners, monitoring tools, and service accounts. Filter them out at query time rather than suppressing the alert entirely -- preserves auditability.

---

## 3. Allowlist Service Accounts from Brute Force Detections

```splunk
index=security sourcetype=wineventlog EventCode=4625
| where NOT match(user,"(?i)(svc_|service_|_svc|_sa|sqlagent|backup)")
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 10
| sort -count
```

Service accounts legitimately generate high volumes of authentication events. Regex-based exclusion is faster than a lookup for well-named service account patterns.

---

## 4. Time-Based Suppression -- Exclude Scheduled Maintenance Windows

```splunk
index=security sourcetype=wineventlog EventCode=4624
| eval hour=strftime(_time,"%H")
| eval day=strftime(_time,"%A")
| eval maintenance=if((day="Sunday" AND hour>=2 AND hour<=4),"YES","NO")
| where maintenance="NO"
| stats count by user, src_ip, dest
```

Patch cycles and backup jobs generate enormous noise during maintenance windows. Time-based suppression keeps analysts focused on actionable alerts.

---

## 5. Measure Alert Fidelity -- True Positive Rate by Rule

```splunk
index=notable
| stats count as total_alerts,
        count(eval(status="closed" AND disposition="true_positive")) as true_positives
        by rule_name
| eval fidelity=round((true_positives/total_alerts)*100,1)
| sort fidelity
| head 20
```

Quantifies which rules have the worst true positive rates. The lowest fidelity rules are your tuning priority. This is the data-driven approach to FP reduction that produces measurable results.

---

## 6. Identify Noisy Rules Generating Duplicate Alerts

```splunk
index=notable
| bucket _time span=1h
| stats count by rule_name, src_ip, dest, _time
| where count > 5
| sort -count
```

Rules firing repeatedly on the same source/destination within a short window are candidates for deduplication via Splunk's notable event suppression or a throttle command.

---

## 7. Throttle Repeated Alerts on Same Entity

```splunk
index=security sourcetype=wineventlog EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 10
| throttle suppress_period=3600 suppress_fields=src_ip
```

The throttle command prevents the same src_ip from generating a new alert more than once per hour -- reduces alert fatigue without losing visibility entirely.

---

## 8. Baseline Normal Behavior Before Setting Thresholds

```splunk
index=security sourcetype=wineventlog EventCode=4625
| bucket _time span=1d
| stats count by _time, src_ip
| eventstats avg(count) as avg_daily, stdev(count) as stdev_daily by src_ip
| eval upper_threshold=round(avg_daily+(stdev_daily*2),0)
| table src_ip, avg_daily, stdev_daily, upper_threshold
| sort -avg_daily
```

Never set alert thresholds arbitrarily. Use statistical baselining to set thresholds at two standard deviations above mean -- this is how you justify threshold decisions to audit and leadership.

---

## 9. Identify Alerts Consistently Closed as False Positives

```splunk
index=notable earliest=-30d
| where status="closed" AND disposition="false_positive"
| stats count by rule_name, src_ip, user
| sort -count
| head 20
```

A 30-day lookback on FP-closed notables reveals systemic suppression candidates. If the same rule/source combination is closed as FP more than 10 times in 30 days, it needs a permanent suppression or rule modification.

---

## 10. Validate Tuning -- Before and After Alert Volume Comparison

```splunk
index=notable
| eval period=if(_time < relative_time(now(),"-7d"),"before","after")
| stats count by rule_name, period
| eval period=if(period="before","before","after")
| xyseries rule_name period count
| eval reduction=round(((before-after)/before)*100,1)
| where isnotnull(reduction)
| sort -reduction
```

Quantifies the impact of tuning changes week-over-week per rule. This is how you produce the data behind a "90% FP reduction" claim -- before and after metrics per detection rule, presentable to leadership and auditors.

---

## Interview Discussion Points

- Lead with the 90% FP reduction story -- explain the methodology: baseline first, identify top contributors, apply layered suppression, measure results
- Distinguish between suppression (hiding alerts) and tuning (improving the rule) -- Wells Fargo's regulatory environment means suppression needs to be documented and justifiable
- Explain how you maintain an audit trail of tuning decisions -- especially important under OCC oversight
- Discuss how you use SOAR to automate repetitive FP triage so analysts focus on genuine threats
- Talk about the feedback loop -- analysts closing FP notables feeds back into tuning priorities
- Key principle: never suppress without documenting why -- in a regulated financial environment, unexplained suppression is an audit finding waiting to happen
