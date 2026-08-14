# CTI Analysis & Rules - Report #27

**Title:** Task scam: AI-assisted fake review jobs
**Category:** Scams / Social Engineering

## 1. Threat Analysis & TTP Mapping
This threat involves scamming victims through fake review jobs, utilizing AI for translation. The threat actors, likely originating from Cambodia, leverage AI-assisted tools to facilitate their social engineering tactics. Mapping to MITRE ATT&CK, this aligns with T1566 (Phishing) and T1623 (Social Engineering), indicating a human-centric attack vector. The translation capability suggests the use of cloud or API-based translation services, potentially tracked under T1695 (Recycling of Known Tactics, Techniques, and Procedures) for evasion and effectiveness enhancement.

## 2. Indicator Extraction
Extracted indicators include: domains related to fake review job postings, IP addresses from Cambodia, suspicious URLs linking to payment sites, and malicious prompt patterns involving requests for payment fees. Anomalies in user-agent strings may indicate automated translation services usage, such as 'OpenAI-Translation' or specific browser versions commonly used in Cambodia.

## 3. Detection Rule Generation
```yaml
{
  "api_misuse_rule": {
    "condition": "translation_api_call and payment_fee_request",
    "action": "flag_as_potential_scam"
  },
  "behavioral_rule": {
    "pattern": "multiple_login_attempts_from_cambodia",
    "threshold": 3,
    "timeframe": "1 hour",
    "action": "alert_security_team"
  }
}
```

## 4. Yara Rules
```yara
rule fake_review_job_scam : scam { meta: description = "Detects scam patterns involving fake review jobs" strings: $translation_pattern = "translate\s+to\s+[a-z]{2}" $payment_fee_request = "pay\s+fee\s+for\s+review" condition: any of them }
```
