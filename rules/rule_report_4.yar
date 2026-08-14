<<<<<<< Updated upstream
rule GPT55_Malicious_Prompt { meta: author = "Threat Intelligence Team" description = "Detects malicious prompts targeting GPT-5.5 vulnerabilities" strings: $a = "exploit" $b = "vulnerability" condition: any of ($a*) or any of ($b*) }
=======
rule GPT_Red_Self_Play_Anomaly { meta: author = "AI Threat Intelligence Engineer" description = "Detects anomalous self-play patterns in GPT-Red" strings: $a = "self-play" $b = "frequency" condition: $a and $b } rule Malicious_Prompt_Injection { meta: author = "AI Threat Intelligence Engineer" description = "Identifies malicious prompt injection attempts against GPT-Red" strings: $c = "malicious prompt pattern 1" $d = "malicious prompt pattern 2" condition: $c or $d }
>>>>>>> Stashed changes
