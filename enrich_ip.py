import json
import requests

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
# Replace this with your actual AbuseIPDB API Key
API_KEY = "97d1a8eb082d14e0f71b41e3362c432254b2be3b3bf4475cec113965b16e5f7daa943dfba294c517"

# The Indicator of Compromise (IoC) we want to enrich
TARGET_IP = "185.220.101.5"


def enrich_ip_address(ip_address, api_key):
    """Queries AbuseIPDB API to enrich an IP address with threat metadata."""
    url = "https://api.abuseipdb.com/api/v2/check"

    # API parameters
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

    # HTTP Headers required by AbuseIPDB
    headers = {"Accept": "application/json", "Key": api_key}

    try:
        # Make the GET request to the API
        response = requests.get(url, headers=headers, params=params)

        # Check if the request was successful (Status Code 200)
        if response.status_code == 200:
            return response.json()["data"]
        else:
            print(
                f"[!] Error: API returned status code {response.status_code}"
            )
            return None

    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None


# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------
if __name__ == "__main__":
    print(f"[*] Querying threat intelligence for IP: {TARGET_IP}...\n")

    # Call our enrichment function
    data = enrich_ip_address(TARGET_IP, API_KEY)

    if data:
        # Extract the key fields an analyst cares about
        abuse_score = data.get("abuseConfidenceScore")
        country = data.get("countryCode")
        isp = data.get("isp")
        domain = data.get("domain")
        total_reports = data.get("totalReports")
        is_tor = data.get("isTor")

        # Display the enriched intelligence summary
        print("=" * 40)
        print(" THREAT INTEL ENRICHMENT REPORT")
        print("=" * 40)
        print(f"IP Address:        {TARGET_IP}")
        print(f"Abuse Score:       {abuse_score}%")
        print(f"Country:           {country}")
        print(f"ISP:               {isp}")
        print(f"Domain:            {domain}")
        print(f"Total Reports:     {total_reports}")
        print(f"Known Tor Node:    {is_tor}")
        print("=" * 40)

        # Simple triage logic based on threshold
        if abuse_score > 50:
            print("ALERT: High confidence malicious indicator!")
        else:
            print("INFO: Low/Moderate risk indicator.")