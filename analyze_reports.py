import os
import sqlite3
import json
from dotenv import load_dotenv
from groq import Groq

# 1. Load secret variables from .env file
load_dotenv()

# 2. Initialize the Groq client
api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key)

# 3. Ensure the output directory for generated rules exists
RULES_DIR = "rules"
os.makedirs(RULES_DIR, exist_ok=True)

# 4. Fetch reports from the database
conn = sqlite3.connect("AI_Model_Abuse.db")
cursor = conn.cursor()

# Query unanalyzed or top threat reports
cursor.execute("SELECT id, title, content, category FROM reports LIMIT 5")
reports = cursor.fetchall()

if not reports:
    print("[*] No reports found in database to analyze.")
    exit(0)

for report in reports:
    report_id, title, content, category = report
    print(f"[*] Analyzing Report #{report_id}: {title} [{category}]...")

    prompt = f"""
    You are an AI Threat Intelligence Engineer & Technical Threat Investigator specializing in LLM platform safety and model abuse.
    
    Analyze the following threat report snippet:
    Title: {title}
    Category Tag: {category}
    Content: {content[:3000]}

    Perform the following tasks:
    1. **Threat Analysis & TTP Mapping**: Identify key threat actor behaviors, model abuse vectors (e.g., Prompt Injection, Jailbreaking, Automated Scraping, Influence Operations, Malware Assistance), and infrastructure usage.
    2. **Indicator Extraction**: Extract any threat actor IOCs (IPs, domains, user-agents, malicious prompts, or API usage anomalies).
    3. **Detection Rule Generation**: Construct a structured API/Platform Misuse Rule or Threat Intel Detection Signature (in JSON or YARA format) to detect or mitigate this threat pattern.
    """

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )

    analysis_output = response.choices[0].message.content

    # Print to console/workflow logs
    print(f"--- ANALYSIS & DETECTION RULE FOR REPORT #{report_id} ---")
    print(analysis_output)
    print("\n" + "="*50 + "\n")

    # Save rule output directly to the rules/ directory
    rule_filename = os.path.join(RULES_DIR, f"detection_rule_report_{report_id}.md")
    with open(rule_filename, "w", encoding="utf-8") as f:
        f.write(f"# Detection Rule & Threat Intel Output - Report #{report_id}\n\n")
        f.write(f"**Title:** {title}\n")
        f.write(f"**Category:** {category}\n\n")
        f.write(analysis_output)

    print(f"[+] Saved generated detection rule to: {rule_filename}")

conn.close()
print("[+] Analysis complete. All generated rules stored in rules/ folder.")