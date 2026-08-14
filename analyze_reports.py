import os
import sqlite3
import json
from dotenv import load_dotenv
from groq import Groq

# 1. Load configuration
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key)

RULES_DIR = "rules"
os.makedirs(RULES_DIR, exist_ok=True)

def stringify_field(value):
    """Converts dicts, lists, or non-string fields into formatted strings for SQLite/Markdown."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value) if value is not None else ""

# 2. Connect to database and ensure table schema exists
conn = sqlite3.connect("AI_Model_Abuse.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT UNIQUE,
        source_type TEXT,
        link TEXT,
        content TEXT,
        published TEXT,
        category TEXT,
        threat_analysis TEXT,
        indicators TEXT,
        detection_rules TEXT,
        yara_rules TEXT
    )
""")

# Check for missing columns if table already existed under an older schema
cursor.execute("PRAGMA table_info(reports)")
existing_cols = [col[1] for col in cursor.fetchall()]
required_cols = {
    "threat_analysis": "TEXT",
    "indicators": "TEXT",
    "detection_rules": "TEXT",
    "yara_rules": "TEXT"
}

for col_name, col_type in required_cols.items():
    if col_name not in existing_cols:
        cursor.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type}")
        print(f"[*] Schema update: Added column [{col_name}]")

conn.commit()

# 3. Query all pending/unanalyzed reports
cursor.execute("""
    SELECT id, title, content, category 
    FROM reports 
    WHERE threat_analysis IS NULL OR threat_analysis = ''
""")
reports = cursor.fetchall()

if not reports:
    print("[*] No pending reports found to analyze. All database rows are up to date.")
    conn.close()
    exit(0)

print(f"[*] Found {len(reports)} report(s) ready for AI analysis.\n")

# 4. Iterate and analyze each report
for report in reports:
    report_id, title, content, category = report
    print(f"[*] Analyzing Report #{report_id}: '{title}' [{category}]...")

    prompt = f"""
    You are an AI Threat Intelligence Engineer & Technical Threat Investigator specializing in LLM platform safety and model abuse.
    Analyze the following threat report snippet:
    
    Title: {title}
    Category: {category}
    Content Snippet: {content[:3000]}

    Provide your response strictly in valid JSON format matching this exact key structure:
    {{
        "threat_analysis": "Detailed threat analysis and TTP mapping to MITRE ATT&CK or MITRE ATLAS",
        "indicators": "Extracted IoCs such as domains, IPs, URLs, malicious prompt patterns, or user-agent anomalies",
        "detection_rules": "API misuse detection rules or behavioral detection logic in YAML/JSON format",
        "yara_rules": "Complete, valid YARA rule syntax targeting identified threat signatures, prompts, or artifacts"
    }}
    """

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )

        data = json.loads(response.choices[0].message.content)
        
        threat_analysis = stringify_field(data.get("threat_analysis"))
        indicators = stringify_field(data.get("indicators"))
        detection_rules = stringify_field(data.get("detection_rules"))
        yara_rules = stringify_field(data.get("yara_rules"))

        # Update SQLite database row
        cursor.execute("""
            UPDATE reports
            SET threat_analysis = ?,
                indicators = ?,
                detection_rules = ?,
                yara_rules = ?
            WHERE id = ?
        """, (threat_analysis, indicators, detection_rules, yara_rules, report_id))
        conn.commit()

        # Save markdown report to rules/ directory
        rule_filename = os.path.join(RULES_DIR, f"detection_report_{report_id}.md")
        with open(rule_filename, "w", encoding="utf-8") as f:
            f.write(f"# CTI Analysis & Rules - Report #{report_id}\n\n")
            f.write(f"**Title:** {title}\n")
            f.write(f"**Category:** {category}\n\n")
            f.write("## 1. Threat Analysis & TTP Mapping\n")
            f.write(f"{threat_analysis}\n\n")
            f.write("## 2. Indicator Extraction\n")
            f.write(f"{indicators}\n\n")
            f.write("## 3. Detection Rule Generation\n")
            f.write(f"```yaml\n{detection_rules}\n```\n\n")
            f.write("## 4. Yara Rules\n")
            f.write(f"```yara\n{yara_rules}\n```\n")

        # Save standalone YARA rule file if populated
        if yara_rules.strip():
            yara_filename = os.path.join(RULES_DIR, f"rule_report_{report_id}.yar")
            with open(yara_filename, "w", encoding="utf-8") as yf:
                yf.write(yara_rules)

        print(f"[+] Successfully saved Report #{report_id} to DB and {RULES_DIR}/\n")

    except Exception as e:
        print(f"[!] Error analyzing Report #{report_id}: {e}\n")

conn.close()
print("✅ All pending reports processed successfully.")