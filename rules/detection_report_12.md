# CTI Analysis & Rules - Report #12

**Title:** Keeping your data safe when an AI agent clicks a link
**Category:** Technical Exploitation

## 1. Threat Analysis & TTP Mapping
The threat report highlights the risk of URL-based data exfiltration and prompt injection when AI agents interact with links. This can be mapped to the MITRE ATT&CK framework, specifically to the 'Data Exfiltration' (TA0010) and 'Command and Control' (TA0011) tactics. The technique used by the threat actors can be identified as 'Phishing' (T1566) and 'Spearphishing Link' (T1566.002). To prevent such attacks, it's essential to implement built-in safeguards, such as URL filtering, input validation, and output encoding, to prevent malicious links from being opened by AI agents.

## 2. Indicator Extraction
No specific IoCs are provided in the given snippet, but potential indicators could include suspicious URL patterns, unusual user-agent headers, or anomalous API request rates. Example indicators might be: 'malicious_link_pattern': '^https?:\/\/([a-zA-Z0-9]\.)+[a-zA-Z]{2,}(\/?|\/[^\s]+)$', 'suspicious_user_agent': 'User-Agent: .*AI.*Agent.*', 'api_request_anomaly': 'rate > 10 requests per minute'

## 3. Detection Rule Generation
```yaml
{
  "rule1": {
    "name": "API Misuse Detection",
    "description": "Detects suspicious API requests that may be used for data exfiltration or prompt injection",
    "condition": "event.action == 'api_request' and event.user_agent =~ '.*AI.*Agent.*' and event.rate > 10"
  },
  "rule2": {
    "name": "URL Filtering",
    "description": "Blocks requests to suspicious URLs that may be used for phishing or malware delivery",
    "condition": "event.action == 'url_request' and event.url =~ '^https?:\\/\\/([a-zA-Z0-9]\\.)+[a-zA-Z]{2,}(\\/?|\\/[^\\s]+)$'"
  }
}
```

## 4. Yara Rules
```yara
{
  "rule1": "rule Suspicious_URL_Pattern { meta: author = \"LLM Safety Team\" description = \"Detects suspicious URL patterns\" strings: $url_pattern = /^https?:\\/\\/([a-zA-Z0-9]\\.)+[a-zA-Z]{2,}(\\/?|\\/[^\\s]+)$/ condition: $url_pattern }",
  "rule2": "rule AI_Agent_User_Agent { meta: author = \"LLM Safety Team\" description = \"Detects suspicious user-agent headers\" strings: $user_agent = /User-Agent: .*AI.*Agent.*/ condition: $user_agent }"
}
```
