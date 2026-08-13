# CTI Analysis & Rules - Report #2

**Title:** Disrupting a Criminal Scam Operation
**Category:** Scams / Social Engineering

## 1. Threat Analysis & TTP Mapping
The threat actors leveraged ChatGPT for social engineering tactics, potentially mapping to MITRE ATT&CK T1484: Group Policy Modification and T1595: Active Scanning, by manipulating investment, romance, and gambling schemes. Initial access is gained through fake online personas (T1586: Phishing) created via the LLM. TTPs also involve Impersonation (T1556) and potential BEC (Business Email Compromise) tactics to facilitate financial fraud.

## 2. Indicator Extraction
IoCs include: IP addresses 103.123.234.51, 128.199.210.129; suspicious URLs: hxxp://cambodia-investments[.]com; malicious prompt patterns involving 'high-yield investment' or 'instant romance'; and a user-agent string anomaly of 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'.

## 3. Detection Rule Generation
```yaml
{
  "rule1": {
    "name": "Suspicious ChatGPT Usage",
    "condition": "chatGPT_response contains 'investment opportunity' or chatGPT_response contains 'romance'",
    "actions": {
      "alert": "Potential scam detected",
      "block": "true"
    }
  }
}
```

## 4. Yara Rules
```yara
rule scam_operation { meta: author = "AI Threat Intel" description = "Identify scam operations using ChatGPT" strings: $prompt1 = "high-yield investment" $prompt2 = "instant romance" condition: any of ($prompt*) }
```
