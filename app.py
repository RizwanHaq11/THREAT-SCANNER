import logging
import re
import socket
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates")
CORS(app)

# API URLs
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY:
    print(f"ABUSEIPDB_API_KEY: {ABUSEIPDB_API_KEY}")
    print(f"VIRUSTOTAL_API_KEY: {VIRUSTOTAL_API_KEY}")
    pass
else:
    logger.error("No API key found.")

# Function to validate IP address
def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

# Function to resolve domain to IP
def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"Resolved domain {domain} to IP {ip}")
        return ip
    except socket.gaierror:
        logger.error(f"Failed to resolve domain: {domain}")
        return None

# Function to check IP in AbuseIPDB
# Function to check IP in AbuseIPDB
def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        logger.error("AbuseIPDB API key is missing")
        return {"error": "API key missing"}
    
    logger.info(f"Checking IP {ip} in AbuseIPDB")
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        
        if response.status_code == 429:
            logger.warning("AbuseIPDB rate limit exceeded")
            return {"error": "Rate limit exceeded"}
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logger.error("AbuseIPDB API request timed out")
        return {"error": "API request timed out"}
    except requests.exceptions.HTTPError as e:
        logger.error(f"AbuseIPDB HTTP error: {e}")
        return {"error": f"HTTP error: {str(e)}"}
    except requests.RequestException as e:
        logger.error(f"Error fetching from AbuseIPDB: {e}")
        return {"error": f"Failed to fetch from AbuseIPDB: {str(e)}"}

# Function to check in VirusTotal
def check_virustotal(ip):
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API key is missing")
        return {"error": "API key missing"}
    
    logger.info(f"Checking IP {ip} in VirusTotal")
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url = f"{VIRUSTOTAL_IP_URL}{ip}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 429:
            logger.warning("VirusTotal quota exceeded")
            return {"error": "API quota exceeded"}
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logger.error("VirusTotal API request timed out")
        return {"error": "API request timed out"}
    except requests.exceptions.HTTPError as e:
        logger.error(f"VirusTotal HTTP error: {e}")
        return {"error": f"HTTP error: {str(e)}"}
    except requests.RequestException as e:
        logger.error(f"Error fetching from VirusTotal: {e}")
        return {"error": f"Failed to fetch from VirusTotal: {str(e)}"}


# Serve HTML page
@app.route('/')
def index():
    logger.info("Serving index.html")
    return render_template("index.html")

# API Endpoint
@app.route('/check', methods=['POST'])
def check_ip():
    data = request.json
    input_value = data.get("ip")

    if not input_value:
        logger.warning("No IP or domain provided in request")
        return jsonify({"error": "No IP or domain provided"}), 400

    logger.info(f"Received request to check: {input_value}")
    
    # Resolve domain to IP if necessary
    if not is_valid_ip(input_value):
        resolved_ip = resolve_domain_to_ip(input_value)
        if not resolved_ip:
            return jsonify({"error": "Invalid domain or could not resolve"}), 400
        input_value = resolved_ip
    
    # Check with AbuseIPDB and VirusTotal
    abuseipdb_result = check_abuseipdb(input_value)
    virustotal_result = check_virustotal(input_value)
    
    # Combine results
    result = {
        "AbuseIPDB": abuseipdb_result,
        "VirusTotal": virustotal_result
    }
    
    logger.info(f"Response for {input_value}: {result}")
    return jsonify(result)

if __name__ == '__main__':
    logger.info("Starting Flask application")
    port = int(os.environ.get("PORT", 5000))  # Default to 5000 if PORT is not set
    app.run(host="0.0.0.0", port=port)
