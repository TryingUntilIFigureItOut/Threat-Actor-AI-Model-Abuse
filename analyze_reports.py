import os
import sqlite3
from dotenv import load_dotenv
from groq import Groq

# 1. Load the secret variables from the .env file
load_dotenv()

# 2. Fetch the loaded key
api_key = os.getenv("GROQ_API_KEY")

# 3. Initialize the Groq client
client = Groq(api_key=api_key)

# The rest of your script follows...
conn = sqlite3.connect("AI_Model_Abuse.db")
cursor = conn.cursor()

cursor.execute("SELECT id, title, content FROM reports LIMIT 1")
report_id, title, content = cursor.fetchone()

prompt = f"""
You are an expert Threat Intelligence Analyst. Analyze this report:
Title: {title}
Content snippet: {content[:3000]}

1. Map TTPs to MITRE ATLAS.
2. Extract IOCs (URLs, IPs, domains).
3. Write a Sigma Detection Rule covering key behaviors.
"""

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": prompt}]
)

print("--- AI ANALYSIS & SIGMA RULE ---")
print(response.choices[0].message.content)