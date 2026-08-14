# CTI Analysis & Rules - Report #9

**Title:** Introducing Lockdown Mode and Elevated Risk labels in ChatGPT
**Category:** Technical Exploitation

## 1. Threat Analysis & TTP Mapping
The introduction of Lockdown Mode and Elevated Risk labels in ChatGPT suggests a response to potential threats related to prompt injection and AI-driven data exfiltration. Mapping to MITRE ATT&CK, this could be related to TTPs such as 'Input Data Manipulation' (T1212) and 'Data Theft' (T1204). These measures aim to prevent adversaries from exploiting the model for malicious purposes, such as extracting sensitive information or manipulating the model's output for harmful intents.

## 2. Indicator Extraction
Potential IoCs include suspicious prompt patterns designed to bypass content filters or inject malicious inputs, anomalous user-agent strings indicating automation or scripting, and unusual API request patterns that could indicate data exfiltration attempts. Specific indicators might include: domains related to known threat actors, IPs with a history of malicious activity, URLs used to host malicious content, or patterns of prompts that seem to be probing the model's defenses.

## 3. Detection Rule Generation
```yaml
{
  "name": "Prompt Injection Detection",
  "description": "Identify potential prompt injection attacks based on API request patterns and content analysis",
  "rule": [
    {
      "condition": "request.content.contains('suspicious_keywords')",
      "action": "flag_for_review"
    },
    {
      "condition": "user_agent.matches('malicious_pattern')",
      "action": "block_request"
    }
  ]
}
```

## 4. Yara Rules
```yara
rule suspicious_prompt { meta: author = "AI Threat Intel" description = "Detects suspicious prompts that could indicate injection attempts" strings: $a = "malicious_keyword" $b = "suspicious_pattern" condition: $a or $b }
```
