# CTI Analysis & Rules - Report #20

**Title:** Scam operations: Online fraud networks
**Category:** Scams / Social Engineering

## 1. Threat Analysis & TTP Mapping
The threat report highlights the use of AI by online fraud networks to support scam operations, including impersonation, translation, and victim engagement. Mapping to MITRE ATT&CK, the tactics observed include Social Engineering (T1566) and Impersonation (T1583). The use of AI to generate scam scripts and translate content maps to the Content Translation (T1583.002) sub-technique. The technique IDs are linked to the fraud networks' ability to use AI-driven tools for malicious purposes, indicating an advanced level of adaptability and resourcefulness in their operations.

## 2. Indicator Extraction
Indicators of compromise (IoCs) may include suspicious patterns in user-generated content, such as AI-generated text with telltale linguistic features (e.g., overuse of transition words, unnatural sentence structure), unusual traffic patterns to and from OpenAI's servers, or accounts showing automated behavior (e.g., rapid consecutive requests). Specific malicious prompt patterns could involve those designed to elicit personal or financial information or to spread disinformation.

## 3. Detection Rule Generation
```yaml
{
  "rule1": {
    "name": "AI-Generated Scam Content Detection",
    "condition": "(event.action == 'text_generation' AND event.input.contains('personal_info_request'))",
    "action": " Flag for review"
  },
  "rule2": {
    "name": "Automated Account Activity Detection",
    "condition": "(event.action == 'consecutive_requests' AND event.count > 5 AND event.time_frame == '1_minute')",
    "action": "Suspend account for verification"
  }
}
```

## 4. Yara Rules
```yara
rule OpenAI_Scam_Scripts { meta: author = "AI Threat Intelligence" description = "Detects AI-generated scam scripts" strings: $a = "Please enter your credit card details" $b = "Download and install the attached software" condition: any of them }
```
