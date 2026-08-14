{
  "rule romance_scam_ai": {
    "meta": {
      "description": "Detects potential romance scam AI artifacts",
      "author": "Threat Intelligence"
    },
    "strings": {
      "$a": {
        "text": "urgent investment opportunity"
      },
      "$b": {
        "text": "send money"
      }
    },
    "condition": "$a and $b"
  }
}