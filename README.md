# Splunk SPL Query Reference

A collection of Splunk Search Processing Language (SPL) query examples organized by security operations function. These queries cover detection engineering, incident response, threat hunting, and alert tuning.

## Important Disclaimer

**These queries are a starting point, not a drop-in solution.**

Every security environment is different. Index names, sourcetypes, field names, and data models vary significantly between organizations depending on how Splunk has been deployed and configured. Thresholds that are appropriate for one environment may generate unacceptable false positive volume -- or miss real threats entirely -- in another.

Before deploying any query from this repository in a production environment:

- Verify that your index and sourcetype names match those used in the queries
- Confirm that field names align with your data sources and any Common Information Model (CIM) normalization in place
- Baseline normal behavior in your environment before setting alert thresholds
- Test in a development or non-production Splunk instance first
- Document any modifications made for tuning purposes
- Establish a review cadence to keep detections current as your environment and the threat landscape evolve

Suppression and allowlisting decisions should always be documented with a business justification, particularly in regulated industries where audit trails are required.

---

## Contents

### [Splunk_Detection_Engineering_Examples.md](./Splunk_Detection_Engineering_Examples.md)
Correlation searches and TTP-based detections aligned to common attack patterns including brute force, lateral movement, persistence, credential dumping, and data exfiltration. Includes MITRE ATT&CK technique mappings.

### [Splunk_Incident_Response_Examples.md](./Splunk_Incident_Response_Examples.md)
Investigative queries for active incident response including scope identification, timeline reconstruction, ransomware indicators, C2 beacon detection, and post-incident executive reporting. Includes MITRE ATT&CK technique mappings.

### [Splunk_Threat_Hunting_Examples.md](./Splunk_Threat_Hunting_Examples.md)
Hypothesis-driven hunt queries covering LOLBin abuse, parent-child process anomalies, DGA detection, reconnaissance activity, and impossible travel. Includes MITRE ATT&CK technique mappings and guidance on operationalizing successful hunts into permanent detections.

### [Splunk_Tuning_FP_Reduction_Examples.md](./Splunk_Tuning_FP_Reduction_Examples.md)
Queries and methodology for identifying false positive contributors, baselining normal behavior, applying layered suppression, measuring alert fidelity, and validating tuning effectiveness. Includes guidance on maintaining audit-ready documentation of tuning decisions.

---

## General Guidance

**Index and sourcetype assumptions** -- Queries reference common index names such as `index=security`, `index=endpoint`, and `index=network`. Adjust these to match your environment's naming conventions.

**Sysmon dependency** -- Several endpoint queries rely on Sysmon event codes. If your environment uses a different EDR or endpoint telemetry source, field names and event codes will differ.

**Thresholds** -- Numeric thresholds (count > 10, MB > 500, etc.) are illustrative starting points. Always baseline your environment before setting production thresholds.

**Lookups** -- Queries referencing lookup tables (e.g., known_good_ips.csv) require those lookup files to be created and populated in your Splunk environment.

**GeoIP** -- The impossible travel query requires GeoIP data to be available via Splunk's `iplocation` command, which depends on a MaxMind database being configured.

---

## Resources

- [Splunk Documentation](https://docs.splunk.com)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Splunk Security Essentials App](https://splunkbase.splunk.com/app/3435)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma) -- vendor-agnostic detection rules that can be converted to SPL
