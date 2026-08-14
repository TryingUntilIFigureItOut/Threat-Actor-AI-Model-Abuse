rule OpenAI_ChatGPT_Exploit {
  meta:
    description = "Identify potential OpenAI ChatGPT exploit attempts"
    author = "AI Threat Intelligence Engineer"
  strings:
    $a = "https://api.openai.com/" ascii
    $b = "chatgpt.googleapis.com" ascii
    $c = "ministryofjustice.uk" ascii
  condition:
    any of ($a, $b, $c)