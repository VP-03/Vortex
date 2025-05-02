#app.py
from flask import Flask, render_template, jsonify, request, abort
import json
import os
import glob
import socket
from datetime import datetime
import logging
from pathlib import Path
from flask import send_from_directory
import geoip2.database
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
# Get the absolute path to the data directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = Flask(__name__)

# Function to find an available port
def find_available_port(start_port=5001, max_attempts=20):
    port = start_port
    for _ in range(max_attempts):  # Fixed syntax error here
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('0.0.0.0', port))
            sock.close()
            return port
        except OSError:
            port += 1
    return None

def read_attack_log():
    try:
        attack_log_path = os.path.join(DATA_DIR, 'attack_log.json')
        print(f"Reading attack log from: {attack_log_path}") # Debug log
        with open(attack_log_path, 'r') as file:
            data = json.load(file)
            print(f"Successfully loaded {len(data)} attack records") # Debug log
            return data
    except Exception as e:
        print(f"Error reading attack log: {e}")
        return []

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/attack-data')
def attack_data():
    try:
        if not os.path.exists('/opt/vortex/data/attack_log.json'):
            return jsonify([])
        with open('/opt/vortex/data/attack_log.json') as f:
            data = json.load(f)
            return jsonify(data)
    except Exception as e:
        print(f'Error reading attack log: {e}')
        return jsonify([])

@app.route('/api/reports')
def reports():
    try:
        report_files = glob.glob('/opt/vortex/data/reports/report_*.json')
        reports = []
        for report_file in sorted(report_files, reverse=True)[:10]:  # Latest 10 reports
            try:
                with open(report_file) as f:
                    report = json.load(f)
                    filename = os.path.basename(report_file)
                    report['file'] = filename
                    reports.append(report)
            except Exception as e:
                logging.error(f"Error processing report file {report_file}: {e}")
                continue
        return jsonify(reports)
    except Exception as e:
        logging.error(f"Error loading reports: {e}")
        return jsonify([])

@app.route('/api/report/<date>')
def report_detail(date):
    try:
        # Security check: ensure date parameter only contains valid characters
        if not all(c.isalnum() or c in '-_' for c in date):
            abort(400, "Invalid date format")
            
        report_file = f'/opt/vortex/data/reports/report_{date}.json'
        if os.path.exists(report_file):
            with open(report_file) as f:
                return jsonify(json.load(f))
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        logging.error(f"Error retrieving report {date}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/reports')
def reports_page():
    return render_template("reports.html")

@app.route('/map')
def map_page():
    return render_template("map.html")

@app.route('/api/map')
def offline_map_data():
    try:
        with open('/opt/vortex/data/attack_log.json') as f:
            attacks = json.load(f)
    except Exception as e:
        logging.error(f"Error loading attack log: {e}")
        return jsonify([])

    # Fallback coordinates for known cities/countries
    fallback_coords = {
        "Cupertino, United States": (37.3230, -122.0322),
        "Chennai, India": (13.0827, 80.2707),
        "Tokyo, Japan": (35.6762, 139.6503),
        "Singapore, Singapore": (1.3521, 103.8198),
        "Montreal, Canada": (45.5017, -73.5673),
        "San Francisco, United States": (37.7749, -122.4194),
    }

    enriched = []

    for attack in attacks:
        if not isinstance(attack, dict):
            continue

        city = attack.get("city", "Unknown")
        country = attack.get("country", "Unknown")
        key = f"{city}, {country}"
        coords = fallback_coords.get(key)

        if coords:
            enriched.append({
                "srcLat": coords[0],
                "srcLon": coords[1],
                "destLat": coords[0] + 0.1,  # Fake dest offset
                "destLon": coords[1] + 0.1,
                "ip": attack.get("ip"),
                "dest_ip": attack.get("dest_ip"),
                "hits": attack.get("hits", 1),
                "type": attack.get("attack_type", "unknown"),
                "severity": attack.get("severity", 1),
                "first_seen": attack.get("first_seen", ""),
                "last_seen": attack.get("last_seen", ""),
                "srcCountry": country,
                "srcCity": city,
                "destCountry": country,
                "destCity": city
            })

    return jsonify(enriched)

@app.route('/dash')
def dashboard():
    return render_template("dash.html")

@app.route('/api/statistics')
def statistics():
    try:
        if not os.path.exists('/opt/vortex/data/attack_log.json'):
            return jsonify({
                "total_attacks": 0,
                "unique_ips": 0,
                "attack_types": {}
            })
        
        with open('/opt/vortex/data/attack_log.json') as f:
            attack_data = json.load(f)
            
        total_attacks = len(attack_data)
        unique_ips = len(set(item.get('ip', '') for item in attack_data if isinstance(item, dict)))
        
        # Count attack types
        attack_types = {}
        for item in attack_data:
            if isinstance(item, dict) and 'type' in item:
                attack_type = item['type']
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        return jsonify({
            "total_attacks": total_attacks,
            "unique_ips": unique_ips,
            "attack_types": attack_types
        })
    except Exception as e:
        logging.error(f"Error generating statistics: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/recent')
def recent():
    try:
        if not os.path.exists('/opt/vortex/data/attack_log.json'):
            return jsonify([])
        
        with open('/opt/vortex/data/attack_log.json') as f:
            attack_data = json.load(f)
        
        # Filter and sort by timestamp (if available)
        valid_attacks = [item for item in attack_data if isinstance(item, dict) and 'ip' in item]
        
        # Sort by timestamp if available, otherwise return the last 10 entries
        if valid_attacks and 'timestamp' in valid_attacks[0]:
            sorted_attacks = sorted(valid_attacks, key=lambda x: x.get('timestamp', ''), reverse=True)
        else:
            sorted_attacks = valid_attacks[-10:] if len(valid_attacks) > 10 else valid_attacks
            
        return jsonify(sorted_attacks[:10])  # Return most recent 10
    except Exception as e:
        logging.error(f"Error retrieving recent attacks: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/data')
def data():
    try:
        if not os.path.exists('/opt/vortex/data/attack_log.json'):
            return jsonify([])

        with open('/opt/vortex/data/attack_log.json') as f:
            attack_data = json.load(f)

        # Clean attack entries
        clean_data = []
        for item in attack_data:
            if isinstance(item, dict) and 'ip' in item and 'hits' in item:
                clean_data.append({
                    'ip': item.get('ip', 'Unknown'),
                    'dest_ip': item.get('dest_ip', 'Unknown'),
                    'attack_type': item.get('attack_type', 'Unknown'),
                    'category': item.get('category', 'Unknown'),
                    'severity': item.get('severity', 0),
                    'country': item.get('country', 'Unknown'),
                    'city': item.get('city', 'Unknown'),
                    'org': item.get('org', 'Unknown'),
                    'isp': item.get('isp', 'Unknown'),
                    'asn': item.get('asn', 'Unknown'),
                    'hits': item.get('hits', 0),
                    'first_seen': item.get('first_seen', ''),
                    'last_seen': item.get('last_seen', ''),
                    'attacks': item.get('attacks', [])
                })

        return jsonify(clean_data)

    except Exception as e:
        logging.error(f"Error loading attack data: {e}")
        return jsonify([])
    
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    available_port = find_available_port()
    if available_port:
        logging.info(f"Starting server on port {available_port}")
        # Write the port to a file so other processes can know which port to use
        with open('/opt/vortex/data/dashboard_port.txt', 'w') as f:
            f.write(str(available_port))
        app.run(host='0.0.0.0', port=available_port)
    else:
        logging.error("Could not find an available port. Please free up ports in the range 5001-5020")