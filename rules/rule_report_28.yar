
rule DPRK_Affiliated_Threat_Actor {
   meta:
      description = "Detects potential DPRK-affiliated threat actor activity"
      author = "Threat Intelligence Team"
   strings:
      $a = "phishing" ascii
      $b = "malware" ascii
      $c = "cryptocurrency" ascii
      $d = "http://example.com/malware" ascii
   condition:
      all of ($a, $b, $c) or $d
}