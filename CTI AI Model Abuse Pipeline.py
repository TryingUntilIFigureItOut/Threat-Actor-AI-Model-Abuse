import os
import sqlite3
import feedparser
from pypdf import PdfReader

DB_NAME = "AI_Model_Abuse.db"

TAXONOMY = {
    "PLATFORM_CONTEXT": [
        "openai", "chatgpt", "gpt-4", "gpt-3.5", "llm", "ai model"
    ],
    "ATTRIBUTION": [
        "state-affiliated", "state-linked", "nation-state", "advanced persistent threat", 
        "apt", "government-backed", "cybercrime syndicate", "threat actor", 
        "malicious actor", "adversarial network", "botnet operator", "proxy actor"
    ],
    "TACTICAL_INTENT": [
        "covert io", "deceptive campaign", "inauthentic behavior", "information operation", 
        "sockpuppet", "narrative manipulation", "mass-generated content", "ai-assisted phishing", 
        "spear-phishing", "task scam", "employment scam", "credential harvesting", 
        "impersonation", "romance scam", "pig butchering", "malware development", 
        "coding assistance", "vulnerability research", "exploit generation", "reconnaissance"
    ],
    "TECHNICAL_TTPS": [
        "prompt injection", "jailbreak", "system prompt leak", "model evasion", 
        "adversarial training", "command and control", "c2", "trojanized software"
    ]
}

def classify_and_filter(text):
    text_lower = text.lower()
    has_platform = any(kw in text_lower for kw in TAXONOMY["PLATFORM_CONTEXT"])
    if not has_platform:
        return False, "Unrelated"

    has_actor = any(kw in text_lower for kw in TAXONOMY["ATTRIBUTION"])
    has_intent = any(kw in text_lower for kw in TAXONOMY["TACTICAL_INTENT"])
    has_ttp = any(kw in text_lower for kw in TAXONOMY["TECHNICAL_TTPS"])

    if not (has_actor or has_intent or has_ttp):
        return False, "General AI"

    if "covert io" in text_lower or "information operation" in text_lower or "sockpuppet" in text_lower:
        category = "IO / Influence Operations"
    elif "malware" in text_lower or "phishing" in text_lower or "exploit" in text_lower:
        category = "Offensive Cyber Operations"
    elif "scam" in text_lower or "impersonation" in text_lower or "harvesting" in text_lower:
        category = "Scams / Social Engineering"
    elif has_actor:
        category = "State / Criminal Attribution"
    else:
        category = "Technical Exploitation"

    return True, category

def init_db():
    conn = sqlite3.connect(DB_NAME)
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
    
    cursor.execute("PRAGMA table_info(reports)")
    columns = [col[1] for col in cursor.fetchall()]
    new_cols = {
        "threat_analysis": "TEXT",
        "indicators": "TEXT",
        "detection_rules": "TEXT",
        "yara_rules": "TEXT"
    }
    
    for col_name, col_type in new_cols.items():
        if col_name not in columns:
            cursor.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type}")
            print(f"[*] Migrated DB: Added column [{col_name}]")

    conn.commit()
    conn.close()

def save_report(title, source_type, link, content, published, category):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO reports (title, source_type, link, content, published, category)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (title, source_type, link, content, published, category))
    conn.commit()
    conn.close()

def parse_pdf_report(pdf_path):
    if not os.path.exists(pdf_path):
        print(f"⚠️ PDF file not found at path: {pdf_path}. Skipping.")
        return

    try:
        reader = PdfReader(pdf_path)
        full_text = "".join([page.extract_text() for page in reader.pages if page.extract_text()])
        
        is_match, category = classify_and_filter(full_text)
        if is_match:
            save_report(os.path.basename(pdf_path), "PDF", pdf_path, full_text, "Historical", category)
            print(f"📄 Saved PDF report under category: [{category}]")
        else:
            print("⏭️ PDF report skipped (did not match threat filtering criteria).")

    except Exception as e:
        print(f"⚠️ Warning: Failed to parse PDF '{pdf_path}'. Skipping file. Error details: {e}")

def fetch_rss_reports(feed_url):
    feed = feedparser.parse(feed_url)
    matched_count = 0
    for entry in feed.entries:
        title = entry.get("title", "")
        summary = entry.get("summary", "")
        content = f"{title} {summary}"

        is_match, category = classify_and_filter(content)
        if is_match:
            save_report(title, "RSS", entry.get("link", ""), summary, entry.get("published", ""), category)
            matched_count += 1
            print(f"📡 Saved RSS entry: '{title[:40]}...' [{category}]")

    print(f"✅ RSS Ingestion finished. Matched {matched_count} threat report(s).")

if __name__ == "__main__":
    init_db()
    parse_pdf_report("disrupting-malicious-uses-of-ai.PDF")
    fetch_rss_reports("https://openai.com/news/rss.xml")