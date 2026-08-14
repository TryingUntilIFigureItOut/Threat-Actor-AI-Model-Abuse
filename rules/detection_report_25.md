# CTI Analysis & Rules - Report #25

**Title:** Vixen and Keyhole Panda: China-linked cyber operations
**Category:** State / Criminal Attribution

## 1. Threat Analysis & TTP Mapping
The threat actors, Vixen and Keyhole Panda, attributed to the People's Republic of China (PRC), have been utilizing OpenAI for malicious purposes including vulnerability research, scripting, translation, and operational troubleshooting. This indicates a potential TTP (Tactics, Techniques, and Procedures) overlap with MITRE ATT&CK framework techniques such as T1583 (Acquire and/or use 3rd party social engineering services), T1599 (Strategic Web Compromise), and T1608 (Stage Capabilities). These actors are leveraging AI to enhance their cyber operations capabilities, suggesting an evolving threat landscape

## 2. Indicator Extraction
Indicators of Compromise (IoCs) may include but are not limited to suspicious API requests, unusual login patterns from Chinese IP addresses, malicious prompt patterns designed to exploit vulnerabilities or bypass security measures, and anomalies in user-agent strings indicating automated or scripted interactions

## 3. Detection Rule Generation
```yaml
{
  "name": "OpenAI Abuse Detection",
  "description": "Detects potential abuse of OpenAI services for malicious activities",
  "logic": {
    "and": [
      {
        "source_ip": {
          "ip": "geoip.country_iso_code:CN"
        }
      },
      {
        "api_request": {
          "uri_path": "/vulnerability/research",
          "method": "POST"
        }
      },
      {
        "user_agent": {
          "regex": ".*script.*|.*automated.*"
        }
      }
    ]
  }
}
```

## 4. Yara Rules
```yara
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
```
