# CTI Analysis & Rules - Report #32

**Title:** The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions
**Category:** Technical Exploitation

## 1. Threat Analysis & TTP Mapping
The threat report snippet highlights the vulnerability of Large Language Models (LLMs) to prompt injections, jailbreaks, and other attacks. This maps to the MITRE ATT&CK framework, specifically to the 'Input Data Manipulation' (T1193) and 'Exploitation for Privilege Escalation' (T1068) techniques. Adversaries aim to overwrite a model's original instructions with malicious prompts, which can lead to unauthorized access, data breaches, or model exploitation. The Instruction Hierarchy concept implies a layered approach to instruction prioritization, which can be exploited to manipulate model behavior.

## 2. Indicator Extraction
Malicious prompt patterns may include SQL injection-like queries, encoded or obfuscated strings, or keyword combinations designed to trigger specific model responses. Specific IoCs are not provided in the snippet, but potential indicators could involve unusual API request patterns, suspicious user-agent headers, or anomalies in model output that suggest instruction manipulation.

## 3. Detection Rule Generation
```yaml
{
  "rule1": {
    "name": "LLM Instruction Manipulation Detection",
    "description": "Identifies potential malicious prompt patterns and API misuse",
    "filter": {
      "pattern": [
        "SQL injection-like queries",
        "encoded or obfuscated strings"
      ],
      "threshold": 0.7
    }
  }
}
```

## 4. Yara Rules
```yara
{
  "rule LLM_Instruction_Manipulation": {
    "meta": {
      "description": "Detects potential LLM instruction manipulation attempts"
    },
    "strings": {
      "prompt_injection": "$sql_injection = /SELECT|INSERT|UPDATE|DELETE/i",
      "obfuscated_string": "$obfuscation = /.*(?:base64|encode|decode).*$/i"
    },
    "condition": "prompt_injection or obfuscated_string"
  }
}
```
