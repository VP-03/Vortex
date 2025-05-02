import requests, logging

def enrich_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        data = r.json()
        logging.info(f"Enrichment for {ip}: {data.get('country', 'Unknown')}, {data.get('org', 'Unknown')}")
        return data
    except Exception as e:
        logging.error(f"IP Enrichment failed for {ip}: {e}")
        return {}
