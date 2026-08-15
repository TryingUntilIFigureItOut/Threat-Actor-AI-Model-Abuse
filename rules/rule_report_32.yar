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