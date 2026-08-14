<<<<<<< Updated upstream
rule OpenAI_Safety_Threat { meta: author = "AI Threat Intel" description = "Detects potential Safety Bug Bounty threats" strings: $a = "excessive recursion" $b = "nested queries" $c = "unknown origin" condition: any of them }
=======
rule TrustedAccessCyber { meta: description = "Detects potential misuse of GPT-5.5 and GPT-5.5-Cyber" condition: any of them }
>>>>>>> Stashed changes
