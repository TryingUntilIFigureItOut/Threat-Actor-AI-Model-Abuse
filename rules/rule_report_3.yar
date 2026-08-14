{
  "rule GPT_Red_Exploitation": "rule GPT_Red_Exploitation { meta: author = \"AI Threat Intelligence Engineer\" description = \"Detects potential GPT-Red exploitation attempts\" strings: $a = \"self-play\" $b = \"/api/self-play\" condition: $a and $b }"
}