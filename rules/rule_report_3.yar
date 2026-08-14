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