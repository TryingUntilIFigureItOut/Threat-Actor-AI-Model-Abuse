{
  "rule localized_model_misuse": {
    "meta": {
      "description": "Detects potential misuse of localized AI models",
      "author": "AI Threat Intelligence Engineer"
    },
    "strings": [
      {
        "keyword": "suspicious_content"
      },
      {
        "keyword": "localized_bias"
      }
    ],
    "condition": "any of them"
  }
}