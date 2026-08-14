# CTI Analysis & Rules - Report #23

**Title:** Operation “Wrong Number”: AI-assisted task scam
**Category:** Scams / Social Engineering

## 1. Threat Analysis & TTP Mapping
The 'Operation Wrong Number' AI-assisted task scam appears to utilize social engineering tactics, potentially mapped to the MITRE ATT&CK framework under T1193 (Spearphishing Attachment), although with an AI-assisted twist. The scammers, reportedly originating from Cambodia, leverage AI to streamline and possibly personalize their scam workflows aimed at individuals in the UK. This suggests an advanced level of organization and technical capability, indicating a potential blend of T1056 (Input Capture) for AI training and T1584 (Netcat) or similar for communication. The use of AI to support scam operations introduces elements of automation and scalability, complicating detection and mitigation efforts.

## 2. Indicator Extraction
Potential indicators of compromise (IoCs) include unusual patterns of AI platform usage, rapid account creation from Cambodian IPs, AI-generated content tailored to UK audiences, and suspicious transaction or communication patterns indicative of scam workflows. Specific IoCs could involve domains used for AI model training, IPs associated with scam communications, URLs for scam websites, or distinctive user-agent strings from automated browsers used in the scam.

## 3. Detection Rule Generation
```yaml
{
  "rule1": {
    "name": "AI-Assisted Scam Detection",
    "description": "Detects unusual AI platform usage patterns indicative of scam operations",
    "condition": "ai_platform_usage_rate > 100 AND geoip_origin == 'Cambodia'",
    "action": "flag_for_review"
  },
  "rule2": {
    "name": "Automated Browser Detection",
    "description": "Identifies suspicious user-agent strings",
    "condition": "user_agent =~ 'automated_browser_signature' AND request_rate > 50",
    "action": "block_request"
  }
}
```

## 4. Yara Rules
```yara
rule Operation_Wrong_Number { meta: author = "AI Threat Intel" description = " Detects Operation 'Wrong Number' AI-assisted scam artifacts" strings: $a = "AI-generated scam pattern" $b = "Cambodia IP address" condition: $a and $b }
```
