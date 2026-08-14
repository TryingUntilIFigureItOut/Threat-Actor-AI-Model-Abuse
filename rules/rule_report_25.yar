{
  "rule vixen_keyhole_panda": {
    "meta": {
      "description": "Detects Vixen and Keyhole Panda threat actors",
      "author": "AI Threat Intelligence"
    },
    "strings": [
      {
        "prompt_pattern": "/vuln|exploit|translate|troubleshoot/"
      },
      {
        "ua_anomaly": "/script|automated|bot/"
      }
    ],
    "condition": "any of strings"
  }
}