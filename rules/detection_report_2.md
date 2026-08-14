# CTI Analysis & Rules - Report #2

**Title:** Disrupting a Criminal Scam Operation
**Category:** Scams / Social Engineering

## 1. Threat Analysis & TTP Mapping
The Cambodia-based scam operation utilized ChatGPT for various social engineering schemes, including investment, romance, gambling, and impersonation scams. This operation's Tactics, Techniques, and Procedures (TTPs) can be mapped to the MITRE ATT&CK framework as follows: T1584 - Compromise Confidentiality (Social Engineering), T1585 - Compromise Integrity (Social Engineering). The threat actors likely exploited the conversational AI capabilities of ChatGPT to craft convincing narratives and manipulate victims into divulging sensitive information or performing certain actions. The use of ChatGPT in these scams also points to the potential for T1556 - Data Manipulation, where threat actors could generate and disseminate false or misleading information to support their schemes.

## 2. Indicator Extraction
Extracted indicators of compromise (IoCs) include: suspicious prompt patterns related to investment, romance, or gambling; Cambodian IP addresses or geolocation data associated with scam traffic; anomalies in user-agent strings indicating automated or scripted interactions with ChatGPT. Specific IoCs may involve URLs related to fake investment platforms, domains used for phishing or impersonation, and unusual patterns of API requests to ChatGPT services.

## 3. Detection Rule Generation
```yaml
{
  "rule1": {
    "name": "Suspicious Prompt Detection",
    "description": "Identify prompts containing keywords related to known scam topics",
    "condition": "prompt.contains('investment') or prompt.contains('romance') or prompt.contains('gambling')",
    "action": "flag_for_review"
  },
  "rule2": {
    "name": "Geolocation Anomaly Detection",
    "description": "Detect requests from high-risk geolocations such as Cambodia",
    "condition": "request.ip.geo.country == 'Cambodia'",
    "action": "increase_suspicion_score"
  }
}
```

## 4. Yara Rules
```yara
rule scam_prompt_detection { strings: $s1 = "investment" $s2 = "romance" $s3 = "gambling" condition: any of ($*) }
```
