# CTI Analysis & Rules - Report #6

**Title:** Designing AI agents to resist prompt injection
**Category:** Technical Exploitation

## 1. Threat Analysis & TTP Mapping
The threat report snippet discusses the design of AI agents to resist prompt injection, which is a technique used by attackers to manipulate AI models into performing unauthorized actions. This can be mapped to the MITRE ATT&CK framework, specifically the 'Input Data Manipulation' tactic (T1204). The AI agent's defense mechanisms, such as constraining risky actions and protecting sensitive data, can be related to the 'Data Protection' and 'Resource Access' techniques (T1485 and T1542). Furthermore, the social engineering aspect of prompt injection can be linked to the 'Phishing' and 'Spearphishing Attachment' techniques (T1566 and T1567) in the MITRE ATT&CK framework.

## 2. Indicator Extraction
No specific IoCs are mentioned in the report snippet, but potential indicators of prompt injection attacks could include: anomalies in user input patterns, unusual API request rates or volumes, suspicious URL parameters, or deviations from expected user-agent behavior. Sample malicious prompt patterns might include: 'Download and execute the file at \\-encoded URL', 'Provide sensitive user information', or 'Perform a specific, unauthorized action'.

## 3. Detection Rule Generation
```yaml
{
  "rules": [
    {
      "name": "Prompt Injection Detection",
      "description": "Detects potential prompt injection attacks by analyzing API request patterns",
      "condition": "api_request_rate > 100 AND user_input_anomaly_score > 0.5",
      "actions": [
        "log_alert",
        "block_request"
      ]
    },
    {
      "name": "Social Engineering Detection",
      "description": "Detects potential social engineering attacks by analyzing user input content",
      "condition": "user_input_content =~ 'sensitive_info|execute|download|unauthorized_action'",
      "actions": [
        "log_alert",
        "block_request"
      ]
    }
  ]
}
```

## 4. Yara Rules
```yara
rule prompt_injection { meta: author = "AI Threat Intelligence Engineer" description = "Detects prompt injection attacks" strings: $s1 = "download and execute" $s2 = "provide sensitive user information" $s3 = "perform unauthorized action" condition: any of ($s*) }
```
