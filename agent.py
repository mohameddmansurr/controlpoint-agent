import os
import json
import requests
import datetime
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_FILE = "cve_data.json"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_API_KEY)

def fetch_latest_cves(hours_lookback=168):
    """
    Phase 1: Fetch Latest CVEs from NVD.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    start_date = now - datetime.timedelta(hours=hours_lookback)
    
    pub_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    pub_end_date = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

    params = {
        'pubStartDate': pub_start_date,
        'pubEndDate': pub_end_date,
        'resultsPerPage': 20
    }

    print(f"[*] Fetching CVEs from {pub_start_date} to {pub_end_date}...")
    
    try:
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            # --- INJECTION FOR DEMO ---
            print("[*] Injecting Demo OT Threat (Siemens PLC)...")
            vulnerabilities.append({
                "cve": {
                    "id": "CVE-2026-99999-DEMO",
                    "descriptions": [{
                        "lang": "en", 
                        "value": "Critical vulnerability in Siemens S7-1500 PLC allows remote attackers to execute arbitrary code via the Modbus TCP protocol."
                    }],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                    }
                }
            })
            # ---------------------------

            print(f"[*] Fetched {len(vulnerabilities)} raw CVEs.")
            return vulnerabilities
        else:
            print(f"[!] API Error: {response.status_code}")
            return []
    except Exception as e:
        print(f"[!] Connection Error: {e}")
        return []

def heuristic_pre_filter(description):
    """
    LAYER 1: The Gatekeeper (Heuristic Pre-filter).
    Calculates a base score based on keyword tiers.
    """
    description_lower = description.lower()
    
    # Tier 1: Strong OT Indicators (Score +40 each)
    tier_1 = ["plc", "scada", "hmi", "dnp3", "modbus", "profibus", "opc ua", "cip", "rtu"]
    
    # Tier 2: Vendor/Context (Score +15 each)
    tier_2 = ["siemens", "rockwell", "schneider", "abb", "honeywell", "ge", "mitsubishi", "omron", "industrial", "ics", "manufacturing", "sensor", "actuator"]
    
    score = 0
    matches = []
    
    for word in tier_1:
        if word in description_lower:
            score += 40
            matches.append(word)
            
    for word in tier_2:
        if word in description_lower:
            score += 15
            matches.append(word)
            
    # Normalize score cap at 95 (leave 100 for LLM verification)
    score = min(score, 95)
    
    return score, matches

def analyze_cve_layered(cve_id, description):
    """
    LAYER 2 & 3: LLM Reasoning & Confidence Scoring.
    """
    
    # --- 1. Heuristic Pre-filter Pass ---
    base_score, keywords = heuristic_pre_filter(description)
    
    # FILTER LOGIC: If score is too low, don't waste API credits
    if base_score < 10:
        return {
            "is_ot": False,
            "confidence": base_score,
            "reason": "Filtered by heuristics (No OT keywords found)."
        }

    # --- 2. LLM Reasoning Pass ---
    # We attempt to use the LLM. If it fails (Rate Limit), we fall back to the base_score.
    
    try:
        prompt = f"""
        Analyze this CVE for Industrial Control Systems (ICS/OT) relevance.
        CVE: {cve_id}
        Desc: {description}
        
        Return JSON:
        {{
            "is_ot": boolean,
            "confidence_score": integer (0-100),
            "reason": "1 sentence explanation"
        }}
        """
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        return {
            "is_ot": result['is_ot'],
            "confidence": result['confidence_score'],
            "reason": result['reason']
        }

    except Exception as e:
        # FALLBACK MODE (If API fails)
        print(f"    [!] LLM Unavailable for {cve_id}, using Heuristic Score: {base_score}%")
        return {
            "is_ot": True, # We assume True because it passed the pre-filter
            "confidence": base_score,
            "reason": f"Heuristic Match: Found keywords {keywords}. (LLM Unavailable)"
        }

def update_database(new_threats):
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'w') as f:
            json.dump([], f)
    
    with open(OUTPUT_FILE, 'r') as f:
        existing_data = json.load(f)
    
    existing_data.extend(new_threats)
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(existing_data, f, indent=4)
    print(f"[*] Database updated. Total records: {len(existing_data)}")

def run_agent():
    raw_cves = fetch_latest_cves(hours_lookback=168)
    ot_threats = []

    print("[*] Starting Layered Analysis...")
    for item in raw_cves:
        cve_item = item['cve']
        cve_id = cve_item['id']
        
        descriptions = cve_item.get('descriptions', [])
        desc_text = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description")
        
        metrics = cve_item.get('metrics', {})
        cvss_score = "N/A"
        if 'cvssMetricV31' in metrics:
            cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']

        # --- RUN ANALYSIS ---
        analysis = analyze_cve_layered(cve_id, desc_text)
        
        if analysis['is_ot']:
            print(f"    [!] OT THREAT DETECTED: {cve_id} (Confidence: {analysis['confidence']}%)")
            report = {
                "cve_id": cve_id,
                "cvss": cvss_score,
                "description": desc_text,
                "ai_insight": analysis['reason'],
                "confidence": analysis['confidence'], # New Field
                "timestamp": datetime.datetime.now().isoformat()
            }
            ot_threats.append(report)
        else:
            # Optional: Print filtered items to show the filter working
            pass

    if ot_threats:
        update_database(ot_threats)
    else:
        print("[*] No new OT threats found.")

if __name__ == "__main__":
    run_agent()
