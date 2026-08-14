# CTI Analysis & Rules - Report #7

**Title:** Improving instruction hierarchy in frontier LLMs
**Category:** Technical Exploitation

## 1. Threat Analysis & TTP Mapping
The IH-Challenge technique is designed to enhance the instruction hierarchy in frontier LLMs, focusing on prioritizing trusted instructions. This approach improves safety steerability and increases resistance to prompt injection attacks. Mapping to MITRE ATT&CK, this technique aligns with T1583 (Acquire and/or Breed New Capabilities) and T1556 (Modify System Configuration), as it involves modifying the model's configuration to improve its resistance to adversarial inputs. From a TTP (Tactics, Techniques, and Procedures) perspective, the adversary is attempting to leverage the improved instruction hierarchy for potential malicious purposes, such as evading content filters or manipulating the model's output.

## 2. Indicator Extraction
No specific IoCs like domains, IPs, or URLs are directly mentioned in the provided content snippet. However, potential indicators could include anomalies in user behavior, such as unusual patterns of instruction submission or prompt crafting that aims to bypass the improved instruction hierarchy. Malicious prompt patterns might involve overly complex or nested instructions designed to test the model's resistance to prompt injection attacks.

## 3. Detection Rule Generation
```yaml
{
  "rule_name": "IH-Challenge Detection",
  "description": "Detects attempts to bypass improved instruction hierarchy in LLMs",
  "condition": "instruction.priority > threshold AND prompt.complexity > nested_threshold",
  "action": "flag_for_review"
}
```

## 4. Yara Rules
```yara
rule IH_Challenge_Detection { meta: description = "Detects IH-Challenge related prompts and instructions" condition: $a = "prioritize" and $b = "trusted" and $c = "instructions" }
```
