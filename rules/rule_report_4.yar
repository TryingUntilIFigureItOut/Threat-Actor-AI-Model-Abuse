{
  "rule1": "rule GPT55_Malicious_Prompt { strings: $a = \"vulnerability research\" $b = \"exploit\" condition: $a and $b }",
  "rule2": "rule GPT55_Cyber_Anomaly { strings: $c = \"unauthorized access\" $d = \"sensitive information\" condition: $c or $d }"
}