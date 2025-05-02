import json
import time
import subprocess
import logging
import io
import os
import random
import string
from enrich import enrich_ip
from datetime import datetime
from zoneinfo import ZoneInfo
import shutil
from datetime import datetime, timedelta

USE_ZEEK = True

THRESHOLD = 3  # Lowered threshold for faster detection
ip_hits = {}
ATTACK_LOG = '/opt/vortex/data/attack_log.json'
DEPLOYED_HONEYPOTS = '/opt/vortex/data/deployed_honeypots.json'

# Create directories if they don't exist
os.makedirs('/opt/vortex/data', exist_ok=True)
os.makedirs('/opt/vortex/logs', exist_ok=True)

# Honeypot container options for different attack types
# Using t-pot built-in containers instead of trying to download from Docker Hub
SSH_CONTAINERS = ["cowrie", "heralding"]
MODBUS_CONTAINERS = ["conpot_iec104", "medpot"]
HTTP_CONTAINERS = ["dionaea", "glutton"]
DEFAULT_CONTAINERS = ["honeytrap"]
DDOS_CONTAINERS = ["ddospot"]

# T-POT standard images (might vary depending on T-POT version)
TPOT_IMAGES = {
    "cowrie": "dtagdevsec/cowrie:2204",
    "conpot": "dtagdevsec/conpot:2204",
    "dionaea": "dtagdevsec/dionaea:2204",
    "honeytrap": "dtagdevsec/honeytrap:2204",
    "suricata": "dtagdevsec/suricata:2204",
    "heralding": "custom_heralding:latest",
    "glutton": "dtagdevsec/glutton:2204",
    "medpot": "ghcr.io/telekom-security/medpot:24.04.1",
    "ddospot": "ghcr.io/telekom-security/ddospot:latest",
    "redishoneypot": "ghcr.io/telekom-security/redishoneypot:latest",
    "citrixhoneypot": "ghcr.io/telekom-security/citrixhoneypot:latest"
}

# List of known benign IPs to ignore
BENIGN_IPS = [
    "8.8.8.8",  # Google DNS
    "8.8.4.4",  # Google DNS
    "1.1.1.1",  # Cloudflare DNS
]

def is_benign_ip(ip):
    """Check if IP is in the benign list"""
    return ip in BENIGN_IPS

def get_internal_network_cidr():
    """Get the internal network CIDR for T-POT"""
    try:
        cmd = ["ip", "a"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if "inet" in line and not "127.0.0.1" in line:
                # Extract IP and CIDR notation
                parts = line.strip().split()
                for part in parts:
                    if "/" in part and part.startswith(("10.", "172.", "192.")):
                        return part
        return None
    except Exception as e:
        logging.error(f"Error getting internal network: {e}")
        return None

def generate_random_name():
    """Generate a random container name for obfuscation"""
    prefix = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))
    return f"{prefix}-honeypot"

def list_running_honeypots():
    """List all running honeypot containers"""
    try:
        # Just list all containers using simpler command with no filters
        result = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            containers = result.stdout.strip().split('\n')
            # Filter for honeypot containers (those with 'honeypot' in name or from our lists)
            honeypots = []
            for c in containers:
                if c and ('honeypot' in c or 
                         any(h in c for h in SSH_CONTAINERS + MODBUS_CONTAINERS + 
                             HTTP_CONTAINERS + DEFAULT_CONTAINERS)):
                    honeypots.append(c)
            
            if honeypots:
                logging.info(f"Running honeypots: {', '.join(honeypots)}")
                return honeypots
            else:
                logging.info("No honeypot containers running")
                return []
        else:
            logging.error(f"Error listing containers: {result.stderr}")
            return []
    except Exception as e:
        logging.error(f"Error listing honeypots: {e}")
        return []

def save_honeypot_status():
    """Save the current status of honeypots to a file"""
    try:
        honeypots = list_running_honeypots()
        status = {
            'timestamp':  datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(),
            'honeypots': honeypots
        }
        
        os.makedirs(os.path.dirname(DEPLOYED_HONEYPOTS), exist_ok=True)
        
        with open(DEPLOYED_HONEYPOTS, 'w') as f:
            json.dump(status, f, indent=4)
            
        logging.info(f"Saved honeypot status: {len(honeypots)} active honeypots")
    except Exception as e:
        logging.error(f"Error saving honeypot status: {e}")

def get_tpot_network():
    """Get the correct network to use with T-POT containers"""
    try:
        # Check which networks exist
        networks_cmd = ["docker", "network", "ls", "--format", "{{.Name}}"]
        result = subprocess.run(networks_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        networks = result.stdout.strip().split('\n')
        
        # Look for T-POT networks in preferred order
        if 'macvlan' in networks:
            return 'macvlan'
        elif 'tpot' in networks:
            return 'tpot'
        elif 'bridge' in networks:
            return 'bridge'
        else:
            return ''  # Empty string means use default network
    except Exception as e:
        logging.error(f"Error getting T-POT network: {e}")
        return ''  # Use default network on error

logging.basicConfig(filename='/opt/vortex/logs/vortex.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

import time
logging.Formatter.converter = lambda *args: time.localtime(time.mktime(datetime.now(ZoneInfo('Asia/Kolkata')).timetuple()))
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

def ensure_suricata_running():
    try:
        check_cmd = ["docker", "ps", "--format", "{{.Names}}"]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if any("suricata" in c.lower() for c in result.stdout.strip().split('\n')):
            return True
        network = get_tpot_network()
        network_args = ["--network", network] if network else []
        cmd = ["docker", "run", "-d", "--name", "suricata"]
        if network_args:
            cmd.extend(network_args)
        cmd.append(TPOT_IMAGES.get("suricata", "dtagdevsec/suricata:2204"))
        subprocess.run(cmd)
        return True
    except Exception as e:
        logging.error(f"Suricata run error: {e}")
        return False

def ensure_zeek_running():
    """Ensure Zeek container is running"""
    try:
        cmd = ["docker", "ps", "-a", "--format", "{{.Names}}"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        existing_containers = result.stdout.strip().split('\n')

        if "zeek" in existing_containers:
            # Check if running
            running_cmd = ["docker", "ps", "--format", "{{.Names}}"]
            running_result = subprocess.run(running_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            running_containers = running_result.stdout.strip().split('\n')

            if "zeek" in running_containers:
                logging.info("Zeek container already running")
                return True
            else:
                # Exists but not running, start it
                start_cmd = ["docker", "start", "zeek"]
                subprocess.run(start_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                logging.info("Started existing Zeek container")
                return True

        # If not existing at all, pull image and run
        subprocess.run(["docker", "pull", "zeek/zeek:latest"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        network = get_tpot_network()
        cmd = ["docker", "run", "-d", "--name", "zeek"]
        if network:
            cmd += ["--network", network]
        cmd.append("zeek/zeek:latest")

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            logging.info("Zeek container started successfully")
            return True
        else:
            logging.error(f"Failed to start Zeek container: {result.stderr}")
            return False
    except Exception as e:
        logging.error(f"Error ensuring Zeek is running: {e}")
        return False

def get_zeek_logs():
    """Fetch Zeek connection and SSL logs"""
    try:
        ensure_zeek_running()
        cmd = ["docker", "exec", "zeek", "cat", "/opt/zeek/logs/current/conn.log"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        logs = result.stdout.strip().splitlines() if result.returncode == 0 else []
        return logs
    except Exception as e:
        logging.error(f"Error fetching Zeek logs: {e}")
        return []

def deploy_container(container_type, attack_ip=None, attack_signature=None):
    """Deploy a container with optional obfuscation and smart selection"""

    def smart_select(container_list, signature="", attack_type=""):
        if attack_type == "MODBUS":
            return "conpot_iec104" if "iec" in (signature or "").lower() else "medpot"
        elif attack_type == "HTTP":
            return "glutton" if "glutton" in (signature or "").lower() else "dionaea"
        elif attack_type == "SSH":
            return "heralding" if "herald" in (signature or "").lower() else "cowrie"
        return random.choice(container_list)


    try:
        # Select appropriate container
        if container_type == "SSH":
            container_name = smart_select(SSH_CONTAINERS, attack_signature, container_type)
        elif container_type == "Modbus":
            container_name = smart_select(MODBUS_CONTAINERS, attack_signature, container_type)
        elif container_type == "HTTP":
            container_name = smart_select(HTTP_CONTAINERS, attack_signature, container_type)
        elif container_type == "DDOS":
            container_name = smart_select(DDOS_CONTAINERS, attack_signature, container_type)
        else:
            container_name = smart_select(DEFAULT_CONTAINERS, attack_signature, container_type)

        container_image = TPOT_IMAGES.get(container_name, f"dtagdevsec/{container_name}:2204")

        # Check existing containers
        check_cmd = ['docker', 'ps', '-a', '--format', '{{.Names}}']
        check_result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        existing_containers = check_result.stdout.strip().split('\n')

        if container_name in existing_containers:
            run_check = ['docker', 'ps', '--format', '{{.Names}}']
            run_result = subprocess.run(run_check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            running_containers = run_result.stdout.strip().split('\n')

            if container_name in running_containers:
                logging.info(f"[+] Container already running: {container_name}")
            else:
                subprocess.run(['docker', 'start', container_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logging.info(f"[+] Started existing container: {container_name}")
        else:
            obfuscated_name = generate_random_name()
            network = get_tpot_network()
            network_args = ["--network", network] if network else []

            cmd = ['docker', 'run', '-d', '--name', obfuscated_name]
            if network_args:
                cmd.extend(network_args)
            cmd.append(container_image)

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                logging.info(f"[+] Deployed new container: {container_name} as {obfuscated_name}")
                if attack_ip:
                    logging.info(f"[+] Deployed in response to attack from {attack_ip}")
            else:
                logging.error(f"[-] Failed to deploy container: {result.stderr}")
                fallback_cmd = ['docker', 'run', '-d', '--name', obfuscated_name]
                if network_args:
                    fallback_cmd.extend(network_args)
                fallback_cmd.append(f"dtagdevsec/{container_name}:latest")

                result = subprocess.run(fallback_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    logging.info(f"[+] Deployed fallback container: {container_name} as {obfuscated_name}")
                else:
                    logging.error(f"[-] Fallback deployment failed: {result.stderr}")
                    return False

        save_honeypot_status()
        return True

    except Exception as e:
        logging.error(f"[-] Container deployment error: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def check_suricata_installed():
    """Check if Suricata is installed in T-POT"""
    try:
        cmd = ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        images = result.stdout.strip().split('\n')
        for image in images:
            if "suricata" in image.lower():
                return True
        
        return False
    except Exception as e:
        logging.error(f"Error checking Suricata installation: {e}")
        return False

def ensure_suricata_running():
    """Make sure Suricata is running and properly configured"""
    try:
        # Check if suricata container exists
        check_cmd = ["docker", "ps", "-a", "--format", "{{.Names}}"]
        check_result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        containers = check_result.stdout.strip().split('\n')
        
        suricata_container = None
        for container in containers:
            if "suricata" in container.lower():
                suricata_container = container
                break
        
        if not suricata_container:
            # Check if the image is available
            if check_suricata_installed():
                # Create and start the container
                network = get_tpot_network()
                network_args = ["--network", network] if network else []
                
                cmd = ["docker", "run", "-d", "--name", "suricata"]
                if network_args:
                    cmd.extend(network_args)
                cmd.append(TPOT_IMAGES.get("suricata", "dtagdevsec/suricata:2204"))
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    logging.info("Created and started Suricata container")
                    return True
                else:
                    logging.error(f"Failed to create Suricata container: {result.stderr}")
                    return False
            else:
                logging.error("Suricata image not found in T-POT installation")
                return False
        
        # If suricata container exists, check if it's running
        running_cmd = ["docker", "ps", "--format", "{{.Names}}"]
        running_result = subprocess.run(running_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        running_containers = running_result.stdout.strip().split('\n')
        
        if suricata_container in running_containers:
            logging.info("Suricata container is running")
            return True
        
        # Container exists but not running, start it
        start_cmd = ["docker", "start", suricata_container]
        start_result = subprocess.run(start_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if start_result.returncode == 0:
            logging.info("Started existing Suricata container")
            return True
        else:
            logging.error(f"Failed to start Suricata container: {start_result.stderr}")
            return False
            
    except Exception as e:
        logging.error(f"Error ensuring Suricata is running: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def get_suricata_logs_direct():
    """Try to get Suricata logs directly from the file system"""
    try:
        # T-POT typically mounts logs to the host system
        possible_paths = [
            "/data/suricata/log/eve.json",
            "/opt/tpot/data/suricata/log/eve.json",
            "/data/suricata/log/suricata_ews.log"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    # Read last 100 lines (adjust as needed)
                    lines = f.readlines()[-100:]
                    
                events = []
                for line in lines:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                
                logging.info(f"Read {len(events)} events from Suricata log file")
                return events
        
        logging.warning("Could not find Suricata log files")
        return []
    except Exception as e:
        logging.error(f"Error reading Suricata logs directly: {e}")
        return []

def get_suricata_logs():
    try:
        if not ensure_suricata_running():
            logging.warning("Could not ensure Suricata is running, trying direct log access")
            return get_suricata_logs_direct()

        check_cmd = ["docker", "ps", "--format", "{{.Names}}"]
        check_result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        suricata_container = None
        for container in check_result.stdout.strip().split('\n'):
            if "suricata" in container.lower():
                suricata_container = container
                break
        
        if not suricata_container:
            logging.warning("Suricata container not found, trying direct log access")
            return get_suricata_logs_direct()

        cmd = ["docker", "exec", suricata_container, "tail", "-n", "100", "/var/log/suricata/eve.json"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)

        if result.returncode == 0:
            logs = result.stdout.strip()
            if logs:
                events = []
                for line in io.StringIO(logs):
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                logging.info(f"Fetched {len(events)} events from Suricata")
                return events
            else:
                logging.warning("No logs returned from Suricata, trying direct log access")
                return get_suricata_logs_direct()
        else:
            logging.error(f"Error running docker exec: {result.stderr}")
            return get_suricata_logs_direct()
    except Exception as e:
        logging.error(f"Error fetching Suricata logs: {e}")
        return get_suricata_logs_direct()
    
def get_crowdsec_alerts():
    """Fetch CrowdSec alerts (simplified parsing)"""
    try:
        cmd = ["docker", "logs", "--tail", "100", "crowdsec"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        logs = result.stdout.strip().splitlines() if result.returncode == 0 else []
        return logs
    except Exception as e:
        logging.error(f"Error fetching CrowdSec alerts: {e}")
        return []

def process_attack(src_ip, dest_ip, signature, category, severity, event_time=None):
    """Handles enrichment, logging, and deployment for an attack"""

    # Track hit count
    ip_hits[src_ip] = ip_hits.get(src_ip, 0) + 1

    # Enrich IP (geolocation etc.)
    try:
        enrichment_data = enrich_ip(src_ip)
    except Exception as e:
        logging.error(f"Error enriching IP {src_ip}: {e}")
        enrichment_data = {}

    # Timestamp in IST
    timestamp = event_time if event_time else datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')

    # Identify attack type based on signature
    sig = signature.lower()
    attack_type = "DEFAULT"

    if any(x in sig for x in ['sql', 'injection']):
        attack_type = "SQLI"
    elif 'xss' in sig:
        attack_type = "XSS"
    elif 'csrf' in sig:
        attack_type = "CSRF"
    elif any(x in sig for x in ['http', 'web', 'apache', 'nginx']):
        attack_type = "HTTP"
    elif any(x in sig for x in ['ssh', 'bruteforce']):
        attack_type = "SSH"
    elif any(x in sig for x in ['modbus', 'dnp3', 'scada', 'plc', 'industrial control']):
        attack_type = "MODBUS"
    elif any(x in sig for x in ['ddos', 'udp flood', 'syn flood']):
        attack_type = "DDOS"

    # Prepare attack log entry
    attack_info = {
        'ip': src_ip,
        'dest_ip': dest_ip,
        'attack_type': attack_type,
        'category': category,
        'severity': severity,
        'country': enrichment_data.get('country', 'Unknown'),
        'city': enrichment_data.get('city', 'Unknown'),
        'org': enrichment_data.get('org', 'Unknown'),
        'isp': enrichment_data.get('isp', 'Unknown'),
        'asn': enrichment_data.get('as', 'Unknown'),
        'hits': 1,
        'timestamp': timestamp
    }

    # ✅ Always log the attack, even if it doesn't meet threshold
    log_attack(attack_info)

    # ✅ Deploy honeypot only when threshold is met
    if ip_hits[src_ip] >= THRESHOLD:
        logging.info(f"Threshold met for {src_ip} — deploying {attack_type} honeypot")
        deploy_container(attack_type, src_ip, signature)
        ip_hits[src_ip] = 0
        
def parse_log():
    """Parse Suricata, Zeek, and (optional) CrowdSec logs and update IP hits"""
    alerts_processed = 0

    # --- Process Suricata ---
    events = get_suricata_logs()
    for entry in events:
        try:
            if entry.get('event_type') == 'alert':
                src_ip = entry.get('src_ip', 'Unknown')
                dest_ip = entry.get('dest_ip', 'Unknown')
                signature = entry.get('alert', {}).get('signature', 'Unknown')
                category = entry.get('alert', {}).get('category', 'Unknown')
                severity = entry.get('alert', {}).get('severity', 0)
                event_time = entry.get('timestamp', None)

                if is_benign_ip(src_ip):
                    continue

                if severity < 3:
                    continue  # Skip only if truly low-severity/noise alert

                internal_network = get_internal_network_cidr()
                if internal_network:
                    internal_base = internal_network.split('/')[0].rsplit('.', 1)[0]
                    if src_ip.startswith(internal_base) and dest_ip.startswith(internal_base):
                        continue  # Only skip if BOTH are internal

                if src_ip == 'Unknown' or not src_ip:
                    continue

                if any(x in signature.lower() for x in ["external ip lookup", "dns lookup", "ntp", "heartbeat", "ping"]):
                    continue
                
                process_attack(src_ip, dest_ip, signature, category, severity, event_time)
                alerts_processed += 1

        except Exception as e:
            logging.error(f"Error processing Suricata entry: {e}")
            import traceback
            logging.error(traceback.format_exc())

    # --- Process Zeek ---
    if USE_ZEEK:
        try:
            zeek_logs = get_zeek_logs()
            for line in zeek_logs:
                parts = line.split()
                if len(parts) >= 9:
                    src_ip = parts[2]
                    dest_ip = parts[4]
                    if not is_benign_ip(src_ip) and src_ip != "-" and dest_ip != "-":
                        process_attack(src_ip, dest_ip, "Zeek Connection", "Connection", 2)
                        alerts_processed += 1
        except Exception as e:
            logging.error(f"Error processing Zeek logs: {e}")

    # --- (Optional) Process CrowdSec ---
    if False:  # Set True if you integrate CrowdSec
        try:
            crowdsec_logs = get_crowdsec_alerts()
            for line in crowdsec_logs:
                if "ip:" in line:
                    src_ip = line.split("ip:")[1].split()[0]
                    dest_ip = "Unknown"
                    if not is_benign_ip(src_ip):
                        process_attack(src_ip, dest_ip, "CrowdSec Alert", "Behavioral Detection", 2)
                        alerts_processed += 1
        except Exception as e:
            logging.error(f"Error processing CrowdSec logs: {e}")

    if alerts_processed > 0:
        logging.info(f"Processed {alerts_processed} relevant alerts (Suricata + Zeek + CrowdSec)")
    return alerts_processed

def log_attack(attack_info):
    try:
        os.makedirs(os.path.dirname(ATTACK_LOG), exist_ok=True)
        # Load existing data
        try:
            with open(ATTACK_LOG, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        except FileNotFoundError:
            data = []
            
        if not isinstance(data, list):
            data = []

        # Match on both IP and attack type
        found = False
        for item in data:
            if isinstance(item, dict) and item.get('ip') == attack_info['ip'] and item.get('attack_type') == attack_info['attack_type']:
                item['hits'] = item.get('hits', 0) + attack_info['hits']
                item['last_seen'] = attack_info['timestamp']
                
                # Avoid duplicates in attack list
                existing_attacks = set(item.get('attacks', []))
                existing_attacks.add(attack_info['attack_type'])
                item['attacks'] = list(existing_attacks)

                found = True
                break

        if not found:
            attack_info['attacks'] = [attack_info['attack_type']]
            attack_info['first_seen'] = attack_info['timestamp']
            attack_info['last_seen'] = attack_info['timestamp']
            data.append(attack_info)

        with open(ATTACK_LOG, 'w') as f:
            json.dump(data, f, indent=4)

        logging.info(f"Attack logged: {attack_info['ip']} - {attack_info['attack_type']}")
    
    except Exception as e:
        logging.error(f"Error logging attack: {e}")
        import traceback
        logging.error(traceback.format_exc())

def generate_reports():
    """Generate summary reports for insights"""
    try:
        if not os.path.exists(ATTACK_LOG):
            logging.warning("No attack log found, skipping report generation")
            return
            
        with open(ATTACK_LOG, 'r') as f:
            data = json.load(f)

        if not data:
            logging.warning("No attack data found, skipping report generation")
            return
            
        # Generate daily report
        report_dir = '/opt/vortex/data/reports'
        os.makedirs(report_dir, exist_ok=True)

        today = time.strftime('%Y-%m-%d')
        report_file = f"{report_dir}/report_{today}.json"

        # Group by country
        countries = {}
        attack_types = {}
        total_attacks = 0
        
        for attack in data:
            country = attack.get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + attack.get('hits', 0)

            for attack_type in attack.get('attacks', []):
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

            total_attacks += attack.get('hits', 0)

        # Get currently deployed honeypots
        active_honeypots = list_running_honeypots()

        report = {
            'date': today,
            'total_attacks': total_attacks,
            'unique_ips': len(data),
            'countries': countries,
            'attack_types': attack_types,
            'active_honeypots': active_honeypots,
            'top_attackers': sorted(data, key=lambda x: x.get('hits', 0), reverse=True)[:10]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)

        logging.info(f"Generated daily report: {report_file}")
        return report
    except Exception as e:
        logging.error(f"Error generating reports: {e}")
        return None

def check_and_fix_tpot_setup():
    """Check and fix common T-POT configuration issues"""
    try:
        logging.info("Checking T-POT configuration...")
        
        # Check if we can connect to Docker
        try:
            docker_cmd = ["docker", "info"]
            docker_result = subprocess.run(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if docker_result.returncode != 0:
                logging.error(f"Docker connection issue: {docker_result.stderr}")
                return False
        except Exception as e:
            logging.error(f"Docker connection error: {e}")
            return False
        
        # Check if T-POT services are running
        try:
            # This checks if the T-POT core services are running
            systemctl_cmd = ["systemctl", "status", "tpot"]
            systemctl_result = subprocess.run(systemctl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "running" not in systemctl_result.stdout:
                logging.warning("T-POT service may not be running properly")
        except:
            logging.warning("Could not check T-POT service status")
        
        # Check Suricata status
        ensure_suricata_running()
        
        # Verify honeypots are on the correct network
        network = get_tpot_network()
        if network:
            logging.info(f"Using Docker network: {network}")
        else:
            logging.warning("No specific Docker network identified, using default")
        
        # List current honeypots
        honeypots = list_running_honeypots()
        if honeypots:
            logging.info(f"Found {len(honeypots)} active honeypots")
        else:
            logging.warning("No active honeypots found, deploying default honeypots")
            deploy_status1 = deploy_container("SSH")
            time.sleep(2)  # Small delay between deployments
            deploy_status2 = deploy_container("HTTP")
            
            if not (deploy_status1 or deploy_status2):
                logging.error("Failed to deploy default honeypots")
            
        return True
    except Exception as e:
        logging.error(f"Error checking T-POT setup: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def check_kali_connectivity():
    """Check if attacks from Kali VM are properly detected"""
    try:
        # Get internal network info
        internal_network = get_internal_network_cidr()
        if internal_network:
            logging.info(f"Internal network identified as: {internal_network}")
        else:
            logging.warning("Could not identify internal network")
            
        # Log current detected attacks
        try:
            if os.path.exists(ATTACK_LOG):
                with open(ATTACK_LOG, 'r') as f:
                    data = json.load(f)
                    if data and isinstance(data, list):
                        logging.info(f"Current attack log contains {len(data)} entries")
                        # Print most recent attack
                        if data:
                            recent = sorted(data, key=lambda x: x.get('last_seen', ''), reverse=True)[0]
                            logging.info(f"Most recent attack: {recent.get('ip')} - {recent.get('attack_type')} at {recent.get('last_seen')}")
        except Exception as e:
            logging.error(f"Error checking attack log: {e}")
    except Exception as e:
        logging.error(f"Error checking Kali connectivity: {e}")

if __name__ == "__main__":
    logging.info("Vortex dynamic honeypot controller started")
    report_counter = 0
    
    # Initial setup check and fix
    check_and_fix_tpot_setup()
    
    # Initial report of deployed honeypots
    save_honeypot_status()
    
    # Check for Kali connectivity issues
    check_kali_connectivity()
    
    while True:
        try:
            alerts = parse_log()
            
            # Check if we need to deploy some honeypots if none are active
            if alerts == 0 and report_counter % 20 == 0:  # Check every 5 minutes
                if not list_running_honeypots():
                    logging.info("No active honeypots found, deploying defaults")
                    deploy_container("SSH")
                    time.sleep(5)  # Add a delay between deployments
                    deploy_container("HTTP")

            # Generate reports every hour (240 * 15 seconds = 1 hour)
            report_counter += 1
            if report_counter >= 240:
                report = generate_reports()
                save_honeypot_status()
                report_counter = 0
                
                # Also check if Suricata is running
                ensure_suricata_running()

            time.sleep(15)
        except KeyboardInterrupt:
            logging.info("Shutting down Vortex controller")
            break
        except Exception as e:
            logging.error(f"Main loop error: {e}")
            time.sleep(15)  # Continue despite errors