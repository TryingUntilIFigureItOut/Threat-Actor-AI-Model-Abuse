# CTI Analysis & Rules - Report #29

**Title:** Romance-baiting scam: AI-assisted pig butchering workflows
**Category:** Scams / Social Engineering

## 1. Threat Analysis & TTP Mapping
The reported romance-baiting scam utilizes AI-assisted workflows, specifically leveraging machine translation and text generation capabilities to facilitate investment scam conversations under the guise of romance. This tactic aligns with the Social Engineering category, particularly the 'Phishing' (T1566) and 'Spearphishing via Social Media' (T1534) techniques from the MITRE ATT&CK framework. The use of AI to generate convincing content also relates to 'Content Spoofing' (T1582) and 'Impersonation' (T1553). The geographical origin of the banned accounts in Cambodia may indicate a specific threat actor group but requires further investigation for TTP mapping.

## 2. Indicator Extraction
No specific IoCs like domains, IPs, or URLs are provided in the snippet, but the mention of AI-assisted translation and generation of romance and scam conversations suggests potential indicators could include anomalies in language patterns, unusually cohesive or articulate messages from supposed romantic interests, or investment pitches with suspiciously uniform or polished language. User-agent anomalies might also be present if specific browsers or devices are predominantly used by these scammers.

## 3. Detection Rule Generation
```yaml
{
  "api_misuse": [
    {
      "trigger": "excessive_translation_requests",
      "logic": "rate > 10 AND source == 'romance_or_investment_content'",
      "action": "flag_for_review"
    },
    {
      "trigger": "suspicious_conversation_patterns",
      "logic": "message_content REGEX 'investment' AND message_content REGEX 'urgent'",
      "action": "alert"
    }
  ]
}
```

## 4. Yara Rules
```yara
{
  "rule romance_scam_ai": {
    "meta": {
      "description": "Detects potential romance scam AI artifacts",
      "author": "Threat Intelligence"
    },
    "strings": {
      "$a": {
        "text": "urgent investment opportunity"
      },
      "$b": {
        "text": "send money"
      }
    },
    "condition": "$a and $b"
  }
}
```
