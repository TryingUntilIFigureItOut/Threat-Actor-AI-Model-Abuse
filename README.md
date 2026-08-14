## 🛡️ Threat-Actor AI Model Abuse Intelligence & Detection Pipeline

An automated Cyber Threat Intelligence (CTI) ingestion and detection-engineering pipeline designed to monitor, classify, and generate actionable detection artifacts (YARA rules, behavioral signatures, and IoCs) for threat actor abuse of AI/LLM platforms.

---

## 🎯 Overview

As state-sponsored actors, cybercrime syndicates, and initial access brokers increasingly leverage Large Language Models (LLMs) and Generative AI for offensive cyber operations, covert influence campaigns (IO), social engineering, and malware development, threat telemetry must adapt rapidly.

This project automates the end-to-end intelligence cycle:
1. **Telemetry Ingestion:** Continuously parses multi-format intelligence feeds (vendor research PDFs, official security RSS feeds).
2. **Taxonomy & Filtering:** Classifies intelligence against defined threat taxonomy vectors (Attribution, Tactical Intent, and Technical TTPs).
3. **Structured Storage:** Maintains an embedded SQLite repository (`AI_Model_Abuse.db`) tracking structured indicators and threat narratives.
4. **Autonomous AI Analysis:** Leverages LLM inference (via Groq / `llama-3.3-70b-versatile`) to map activity to **MITRE ATT&CK** / **MITRE ATLAS** and generate YARA detection rules and API misuse behavioral signatures.
5. **CI/CD Automation:** Executes continuously via GitHub Actions on a 12-hour schedule with automated rule and database commits.

---

## 🏗️ Architecture & Pipeline Flow

OpenAI / Industry Feeds
Historical CTI (PDFs)  

▼

CTI AI Model Abuse Pipeline.py  
 • Feed Parsing & Extraction    
 • Taxonomy / Filtering Engine  
 • SQLite Schema Migration     
 
▼

 AI_Model_Abuse.db 
(Raw & Categorized CTI)

▼

analyze_reports.py
 • Groq Llama-3.3-70B Analysis
 • MITRE ATLAS/ATT&CK Mapping
 • Indicator & Signature Gen   

▼

rules/.md                   
(Analysis Brief)

rules/.yar  
(YARA Signatures)

## 📂 Repository Structure

| File / Directory | Description |
| :--- | :--- |
| **`.github/workflows/pipeline.yml`** | GitHub Actions CI/CD workflow running on a 12-hour schedule |
| **`rules/detection_report_*.md`** | AI threat intelligence briefs with MITRE ATLAS mappings & YAML rules |
| **`rules/rule_report_*.yar`** | Standalone YARA detection signatures generated per threat report |
| **`AI_Model_Abuse.db`** | SQLite database tracking raw feeds, categories, IoCs, and rule outputs |
| **`CTI AI Model Abuse Pipeline.py`** | Telemetry ingestion engine, taxonomy filter, and schema migrator |
| **`analyze_reports.py`** | Groq Llama-3.3-70B AI inference and rule generation script |
| **`requirements.txt`** | Python project package dependencies |
| **`disrupting-malicious-uses-of-ai.PDF`** | Seed CTI report utilized for historical telemetry |
| **`README.md`** | Project architecture, taxonomy guide, and setup instructions |

| Category | Description |
| :--- | :--- |
| **`IO / Influence Operations`** | Deceptive campaigns, sockpuppet botnets, inauthentic behavior, narrative manipulation. |
| **`Offensive Cyber Operations`** | AI-assisted malware development, vulnerability research, exploit scripting, and C2 integration. |
| **`Scams / Social Engineering`** | AI-generated spear-phishing, pig butchering, voice/persona impersonation, task scams. |
| **`State / Criminal Attribution`** | Activities linked to nation-state APTs, state-sponsored entities, or cybercrime cartels. |
| **`Technical Exploitation`** | Prompt injection, jailbreaking, system prompt exfiltration, and model evasion. |

## 🚀 Setup & Local Execution
Prerequisites
Python 3.10+

Groq API Key (Get an API Key)

1. Clone the Repository
   git clone [https://github.com/TryingUntilIFigureItOut/Threat-Actor-AI-Model-Abuse.git](https://github.com/TryingUntilIFigureItOut/Threat-Actor-AI-Model-Abuse.git)
cd Threat-Actor-AI-Model-Abuse

2. Install Dependencies
   pip install -r requirements.txt
   (Or install manually: pip install feedparser pypdf groq python-dotenv)

3. Configure Environment Variables
  Create a .env file in the root directory:
  GROQ_API_KEY=your_groq_api_key_here

4. Execute the Pipeline
  Run ingestion and filtering:
  python "CTI AI Model Abuse Pipeline.py"

  Run automated AI analysis and rule generation:
  python analyze_reports.py
  Generated rules and MITRE mappings will be written to the rules/ directory and updated directly inside AI_Model_Abuse.db.


## ⚙️ Automated GitHub Actions Workflow

This repository runs an automated ingestion and analysis cycle every 12 hours via GitHub Actions.

1. Workflow File Location
The workflow configuration is defined in:
`.github/workflows/pipeline.yml`

2. Configure Repository Secrets
To enable AI analysis using Groq, add your API key:
  1. Navigate to **Settings** > **Secrets and variables** > **Actions**.
  2. Click **New repository secret**.
  3. Name: `GROQ_API_KEY`
  4. Secret: `<your-groq-api-key>`

3. Configure Workflow Permissions
Ensure the pipeline bot can commit generated rules and databases back to the repository:
  1. Navigate to **Settings** > **Actions** > **General**.
  2. Under **Workflow permissions**, select **Read and write permissions**.
  3. Click **Save**.

4. Workflow Triggers
  * **Push Event:** Runs on direct commits/merges to `main`.
  * **Scheduled Cron:** Runs automatically every 12 hours (`0 */12 * * *`).
  * **Manual Dispatch:** Run manually anytime via the **Actions** tab.

## 📊 Database Schema (reports Table)

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER` | Primary Key (Auto Increment) |
| `title` | `TEXT UNIQUE` | Threat intelligence report title |
| `source_type` | `TEXT` | RSS or PDF |
| `link` | `TEXT` | Source URL or file path |
| `content` | `TEXT` | Raw report summary/text |
| `published` | `TEXT` | Publication timestamp |
| `category` | `TEXT` | CTI taxonomy classification |
| `threat_analysis` | `TEXT` | AI evaluation & MITRE ATT&CK / ATLAS alignment |
| `indicators` | `TEXT` | Extracted IoCs, domains, prompt patterns, and artifacts |
| `detection_rules` | `TEXT` | Behavioral rules & API misuse logic (YAML) |
| `yara_rules` | `TEXT` | Syntactically valid YARA detection signatures |
