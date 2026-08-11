#!/usr/bin/env python3
import sys
import json
import argparse
import requests
from datetime import datetime

# ================= Configuration =================
ABUSEIPDB_API_KEY = ""
VIRUSTOTAL_API_KEY = ""

# =================================================

def query_abuseipdb(ip, api_key):
    """Query AbuseIPDB API for IP reputation data."""
    if not api_key or api_key == "YOUR_ABUSEIPDB_API_KEY":
        return {"error": "AbuseIPDB API key missing"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": True
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "total_reports": data.get("totalReports"),
                "last_reported_at": data.get("lastReportedAt")
            }
        else:
            return {"error": f"AbuseIPDB HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def query_virustotal(ip, api_key):
    """Query VirusTotal v3 API for IP analysis stats."""
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY":
        return {"error": "VirusTotal API key missing"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "as_owner": attributes.get("as_owner"),
                "reputation": attributes.get("reputation")
            }
        else:
            return {"error": f"VirusTotal HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Automated Threat Intelligence IP Enricher")
    parser.add_argument("ip", help="IP address to enrich")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of human-readable text")
    args = parser.parse_args()

    target_ip = args.ip
    timestamp = datetime.utcnow().isoformat() + "Z"

    abuse_data = query_abuseipdb(target_ip, ABUSEIPDB_API_KEY)
    vt_data = query_virustotal(target_ip, VIRUSTOTAL_API_KEY)

    report = {
        "target_ip": target_ip,
        "timestamp": timestamp,
        "abuseipdb": abuse_data,
        "virustotal": vt_data
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\n==================================================")
        print(f" THREAT INTEL REPORT: {target_ip}")
        print(f" Generated: {timestamp}")
        print(f"==================================================")

        print("\n[+] AbuseIPDB Results:")
        if "error" in abuse_data:
            print(f"    Status: {abuse_data['error']}")
        else:
            print(f"    Confidence Score: {abuse_data['abuse_confidence_score']}%")
            print(f"    Country:          {abuse_data['country_code']}")
            print(f"    ISP:              {abuse_data['isp']}")
            print(f"    Domain:           {abuse_data['domain']}")
            print(f"    Total Reports:    {abuse_data['total_reports']}")

        print("\n[+] VirusTotal Results:")
        if "error" in vt_data:
            print(f"    Status: {vt_data['error']}")
        else:
            print(f"    Detections:       {vt_data['malicious']} Engines Flagged Malicious")
            print(f"    AS Owner:         {vt_data['as_owner']}")
            print(f"    Reputation Score: {vt_data['reputation']}")
        print(f"==================================================\n")


if __name__ == "__main__":
    main()
