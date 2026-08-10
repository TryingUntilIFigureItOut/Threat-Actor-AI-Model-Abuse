import csv
import json
import time
import requests
from github import Auth, Github
from google import genai
import google.genai

# =====================================================================
# CONFIGURATION & KEYS
# =====================================================================
ABUSEIPDB_API_KEY = "97d1a8eb082d14e0f71b41e3362c432254b2be3b3bf4475cec113965b16e5f7daa943dfba294c517"
GEMINI_API_KEY = "AQ.Ab8RN6IM3AMBa-j-w83tWlRxSgShOH1PYjKcVDnZ2B2hQkdHlw"
GITHUB_TOKEN = "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"

# Target GitHub Repository (Format: "username/repository-name")
GITHUB_REPO_NAME = "TryingUntilIFigureItOut/DPRK-IT-Workers-Project"

# Input CSV file containing DPRK threat indicators
INPUT_CSV_FILE = r"C:\Users\dmbro\Python\dprk_indicators.csv"

# Minimum AbuseIPDB confidence score to trigger AI Analysis and Ticketing
RISK_THRESHOLD = 50


# =====================================================================
# STEP 1: ENRICH IP VIA ABUSEIPDB
# =====================================================================
def get_abuseipdb_data(ip_address, api_key):
    """Query AbuseIPDB API for threat telemetry."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": api_key}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()["data"]
        else:
            print(
                f"[!] AbuseIPDB API Error for {ip_address}: Status {response.status_code}"
            )
            return None
    except Exception as e:
        print(f"[!] Request to AbuseIPDB failed for {ip_address}: {e}")
        return None


# =====================================================================
# STEP 2: GENERATE CTI BRIEF VIA GOOGLE GEMINI
# =====================================================================
def generate_gemini_advisory(enriched_data, csv_metadata, gemini_key):
    """Passes enriched telemetry + CSV threat context to Gemini 1.5 Pro."""
    client = genai.Client(api_key=gemini_key)

    system_prompt = (
        "You are a Senior Cyber Threat Intelligence Analyst specializing in DPRK (North Korean) "
        "IT Worker threat operations, laptop farms, and employee recruitment fraud. "
        "Analyze the provided IP telemetry and context to draft a concise executive advisory."
    )

    user_prompt = f"""
    Analyze the following indicator cross-referenced from a North Korean IT Worker threat list:
    
    CSV THREAT CONTEXT:
    - Campaign: {csv_metadata.get('campaign')}
    - Actor Cluster: {csv_metadata.get('threat_actor')}
    - Context Notes: {csv_metadata.get('notes')}
    
    ENRICHED TELEMETRY (AbuseIPDB):
    {json.dumps(enriched_data, indent=2)}

    Format your output strictly using Markdown with the following sections:
    ### Executive Summary
    (2-3 sentences summarizing the threat level, proxy usage, and risk to corporate infrastructure)

    ### Adversary TTPs & Campaign Linkage
    * (List tactics such as VPN/Tor proxy evasion, remote desktop tooling, or laptop farm proxying)

    ### Recommended Mitigation Actions
    1. (Actionable step for HR/IT regarding remote workforce screening)
    2. (Network security block rule or SIEM hunting query)
    3. (Identity/Device isolation step)
    """

    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash-lite",
            contents=user_prompt,
            config=google.genai.types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
            ),
        )
        return response.text
    except Exception as e:
        print(f"[!] Gemini API error: {e}")
        return "Failed to generate AI advisory."


# =====================================================================
# STEP 3: CREATE A GITHUB ISSUE TICKET
# =====================================================================
def create_github_ticket(
    ip_address, score, csv_meta, ai_advisory, github_token, repo_name
):
    """Open an Issue in a designated GitHub repository."""
    try:
        auth = Auth.Token(github_token)
        g = Github(auth=auth)
        repo = g.get_repo(repo_name)

        issue_title = f"🚨 [DPRK CTI ALERT] Malicious Indicator: {ip_address} (Score: {score}%)"
        issue_body = (
            f"## DPRK IT Worker Campaign - Triage Ticket\n\n"
            f"**Target Indicator:** `{ip_address}`\n"
            f"**Campaign:** `{csv_meta.get('campaign')}`\n"
            f"**Threat Actor:** `{csv_meta.get('threat_actor')}`\n"
            f"**Abuse Score:** `{score}%`  \n"
            f"**Timestamp:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`\n\n"
            f"---  \n"
            f"## 🤖 Gemini AI Threat Advisory\n\n"
            f"{ai_advisory}\n"
        )

        new_issue = repo.create_issue(
            title=issue_title,
            body=issue_body,
            labels=["DPRK-IT-Worker", "Automated-Alert"],
        )

        print(
            f"[✓] Ticket created for {ip_address}! View here: {new_issue.html_url}"
        )
        g.close()

    except Exception as e:
        print(f"[!] Failed to create GitHub issue for {ip_address}: {e}")


# =====================================================================
# PIPELINE EXECUTION LOGIC (BATCH PROCESSOR)
# =====================================================================
def process_csv_batch():
    print("==================================================")
    print("   DPRK CTI BATCH ENRICHMENT PIPELINE STARTED     ")
    print("==================================================\n")

    try:
        with open(INPUT_CSV_FILE, mode="r", encoding="utf-8") as infile:
            reader = csv.DictReader(infile)

            for row in reader:
                ip = row["ip"].strip()
                print(f"[*] Processing IP: {ip} ({row['campaign']})...")

                # Step 1: Query AbuseIPDB
                telemetry = get_abuseipdb_data(ip, ABUSEIPDB_API_KEY)

                if telemetry:
                    score = telemetry.get("abuseConfidenceScore", 0)
                    print(f"    - Abuse Score: {score}%")

                    # Step 2: Check Risk Threshold
                    if score >= RISK_THRESHOLD:
                        print(
                            f"    [!] High-risk indicator detected! Generating AI Advisory..."
                        )

                        # Generate AI Advisory using Gemini
                        advisory = generate_gemini_advisory(
                            telemetry, row, GEMINI_API_KEY
                        )

                        # Step 3: Open GitHub Ticket
                        create_github_ticket(
                            ip,
                            score,
                            row,
                            advisory,
                            GITHUB_TOKEN,
                            GITHUB_REPO_NAME,
                        )
                    else:
                        print(
                            f"    [i] Score below threshold ({RISK_THRESHOLD}%). Skipping ticketing."
                        )

                # Rate limiting sleep to respect API limits (1.2 seconds between requests)
                time.sleep(5.0)
                print("-" * 50)

    except FileNotFoundError:
        print(
            f"[!] Error: The file '{INPUT_CSV_FILE}' was not found. Please create it first."
        )


if __name__ == "__main__":
    process_csv_batch()