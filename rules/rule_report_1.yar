<<<<<<< Updated upstream
rule GPT_56_Cyber_Malicious_Prompt { strings: $a = "vulnerability scan" $b = "exploit validation" condition: any of them }
=======
rule malicious_ai_model_usage {
  meta:
    description = "Detects malicious use of AI models for influence operations"
    author = "Threat Intelligence"
  strings:
    $a = "sensitive information"
    $b = "malicious prompt pattern"
  condition:
    $a or $b}
>>>>>>> Stashed changes
