{
  "rule1": "rule Suspicious_URL_Pattern { meta: author = \"LLM Safety Team\" description = \"Detects suspicious URL patterns\" strings: $url_pattern = /^https?:\\/\\/([a-zA-Z0-9]\\.)+[a-zA-Z]{2,}(\\/?|\\/[^\\s]+)$/ condition: $url_pattern }",
  "rule2": "rule AI_Agent_User_Agent { meta: author = \"LLM Safety Team\" description = \"Detects suspicious user-agent headers\" strings: $user_agent = /User-Agent: .*AI.*Agent.*/ condition: $user_agent }"
}