import os
import requests
import pandas as pd
from datetime import datetime
import time

# --- CONFIGURATION ---
# Load all keys from the single Secret string
API_KEYS_STRING = os.environ.get("ABUSE_API_KEYS")
CSV_FILE = "threat_data.csv"

# Convert string to list
API_KEYS = [k.strip() for k in API_KEYS_STRING.split(',')] if API_KEYS_STRING else []

def fetch_data_relay_style():
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    params = {'confidenceMinimum': '75', 'limit': '50'}
    
    print(f"🔄 Relay Started: Checking {len(API_KEYS)} Keys...")
    
    for i, key in enumerate(API_KEYS):
        headers = {'Accept': 'application/json', 'Key': key}
        masked_key = key[-5:] # Security mask
        
        try:
            print(f"   👉 Runner #{i+1} (Key ending ...{masked_key}) is trying...")
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json().get('data', [])
                print(f"      ✅ SUCCESS! Runner #{i+1} got the baton ({len(data)} IPs).")
                print("      🛑 Stopping relay here to save other keys for later.")
                return data # <--- MAGIC LINE: Data milte hi loop tod do
            
            elif response.status_code == 429:
                print(f"      ⚠️ Runner #{i+1} is tired (Limit Reached). Passing baton to next...")
                continue # Agli key try karo
            
            else:
                print(f"      ❌ Runner #{i+1} tripped. Status: {response.status_code}")
                
        except Exception as e:
            print(f"      ❌ Error with Runner #{i+1}: {e}")
            
    print("❌ Race Over: All keys exhausted or failed.")
    return []

def enrich_and_save(raw_data):
    if not raw_data:
        return

    # Remove duplicates just in case
    unique_map = {item['ipAddress']: item for item in raw_data}
    unique_data = list(unique_map.values())
    
    print(f"⚡ Enriching {len(unique_data)} Unique IPs...")
    
    new_rows = []
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    for index, item in enumerate(unique_data):
        ip = item['ipAddress']
        confidence = item['abuseConfidenceScore']
        
        try:
            # Free IP-API for ISP/City details
            geo_url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,mobile,hosting,proxy"
            if index % 5 == 0: time.sleep(0.3) # Be nice to free API
            
            geo = requests.get(geo_url, timeout=2).json()
            
            if geo.get('status') == 'success':
                usage = "Residential/Business"
                if geo.get('hosting'): usage = "Data Center"
                if geo.get('mobile'): usage = "Mobile"
                
                new_rows.append({
                    "Timestamp_UTC": current_time,
                    "IP": ip,
                    "Confidence_Score": confidence,
                    "Country": geo['country'],
                    "City": geo['city'],
                    "ISP": geo['isp'],
                    "Organization": geo['org'],
                    "Usage_Type": usage,
                    "Is_Proxy": geo['proxy']
                })
        except Exception:
            continue

    if new_rows:
        df = pd.DataFrame(new_rows)
        file_exists = os.path.isfile(CSV_FILE)
        
        # Append mode 'a'. Write header only if file is new.
        df.to_csv(CSV_FILE, mode='a', header=not file_exists, index=False)
        print(f"💾 ARCHIVED: Added {len(new_rows)} rows to {CSV_FILE}")
    else:
        print("⚠️ No valid data to save.")

if __name__ == "__main__":
    if not API_KEYS:
        print("❌ CRITICAL: No API Keys found in Secrets!")
    else:
        data = fetch_data_relay_style()
        enrich_and_save(data)
