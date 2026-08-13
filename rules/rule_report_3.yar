
rule GPT_Red_Exploitation {
   meta:
      description = "Detects potential GPT-Red exploitation or misuse"
      author = "AI Threat Intelligence Engineer"
   strings:
      $a = "self-play" nocase
      $b = "prompt injection" nocase
      $c = "automated red teaming" nocase
   condition:
      any of ($a, $b, $c)
}