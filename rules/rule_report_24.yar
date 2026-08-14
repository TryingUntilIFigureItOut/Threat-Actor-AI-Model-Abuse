{
  "rule OperationScopeCreep": {
    "meta": {
      "description": "Identify potential Operation 'ScopeCreep' malware and artifact patterns",
      "author": "AI Threat Intelligence Engineer"
    },
    "strings": [
      "$a = 'exploit'",
      "$b = 'loader>",
      "$c = {4C 69 63 65 6e 73 65}"
    ],
    "condition": "$a and $b or $c"
  }
}