<<<<<<< Updated upstream
{
  "rule GPT_Red_Self_Improvement": {
    "meta": {
      "description": "Detects potential GPT-Red self-improvement patterns in prompts",
      "author": "Threat Intelligence Team"
    },
    "strings": [
      "$s1 = 'self-improvement' ascii wide",
      "$s2 = 'alignment' ascii wide",
      "$s3 = 'safety' ascii wide"
    ],
    "condition": "$s1 or $s2 or $s3"
  }
}
=======
rule ChatGPT_Scam_Operation { meta: author = "AI Threat Intelligence Engineer" description = "Detects potential scam operation prompts in ChatGPT interaction" strings: $prompt_pattern1 = "investment opportunity" $prompt_pattern2 = "romance interest" $prompt_pattern3 = "gambling scheme" condition: any of ($prompt_pattern*) }
>>>>>>> Stashed changes
