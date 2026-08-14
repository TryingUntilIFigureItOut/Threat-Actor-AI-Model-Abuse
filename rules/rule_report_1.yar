{
  "rule GPT_5_6_Cyber_Misuse": {
    "strings": [
      "$a = 'Daybreak Red unauthorized access'",
      "$b = 'GPT-5.6-Cyber exploit attempt'"
    ],
    "condition": "$a or $b"
  }
}