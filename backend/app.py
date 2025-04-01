from flask import Flask, request, jsonify
from flask_cors import CORS
import tldextract
import requests
import whois
import ssl
import re
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib3 import PoolManager
from urllib3.exceptions import SSLError
from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout
from whois.parser import PywhoisError  # Added import for WHOIS exceptions
from web3 import Web3

# Suppress noisy library logs
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

app = Flask(__name__)
CORS(app)
executor = ThreadPoolExecutor(max_workers=8)

# Web3 Configuration
WEB3_PROVIDER = "https://mainnet.infura.io/v3/37b82278bb244b949bf4078fc6ce0e4e"
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))

TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'microsoft.com',
    'paypal.com', 'amazon.com', 'github.com', 'kraken.com',
    'blockfi.com', 'coinbase.com', 'binance.com'
]

BRAND_DOMAINS = {
    'google': ['google.com', 'google.co.in'],
    'paypal': ['paypal.com', 'paypalobjects.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    'microsoft': ['microsoft.com', 'live.com'],
    'kraken': ['kraken.com', 'kraken.io'],
    'blockfi': ['blockfi.com', 'blockfi.net'],
    'coinbase': ['coinbase.com', 'cb.com'],
    'binance': ['binance.com', 'binance.us'],
    'crypto': ['crypto.com', 'nexo.com']
    'sbi': ['sbi.co.in', 'onlinesbi.com'],  
    'hdfcbank': ['hdfcbank.com', 'hdfcsec.com'],  
    'icicibank': ['icicibank.com', 'icicidirect.com'],  
    'axisbank': ['axisbank.com', 'axisdirect.com'],  
    'kotakmahindra': ['kotak.com', 'kotaksecurities.com'],  
    'pnb': ['pnbindia.in', 'pnbcard.in'],  
    'yesbank': ['yesbank.in', 'yessecurities.com'],  
    'paytm': ['paytm.com', 'paytmpaymentsbank.com'],  
    'phonepe': ['phonepe.com', 'phonepe.in'],  
    'npci': ['npci.org.in', 'upi.org.in', 'rupay.co.in'],  
    'indusindbank': ['indusind.com', 'indusindmobile.com'],  
    'bajajfinserv': ['bajajfinserv.in', 'bajajfinservmarkets.in']  
}

GOOGLE_API_KEY = "AIzaSyA5nF2eOEhYvY-GCnHuk4jjPv1LcrwC3J8"

class TLSAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        self.poolmanager = PoolManager(
            ssl_context=ctx,
            num_pools=connections,
            maxsize=maxsize,
            block=block
        )

def is_typosquatting(domain):
    patterns = [
        r'[-_]{2,}', r'\d+[a-z]+\d+', r'(.)\1{3}',
        r'login-', r'verify-', r'secure-', r'account-',
        r'update-', r'wallet-', r'auth-', r'support-',
        r'([a-z])\1{2}', r'[0-9]{5}', r'^www[0-9]'
    ]
    return any(re.search(p, domain, re.IGNORECASE) for p in patterns)

def is_ens_domain(domain):
    return domain.endswith('.eth')

def check_ens_registration(domain):
    try:
        if not is_ens_domain(domain):
            return {'is_ens': False}
        
        namehash = Web3.ens.namehash(domain)
        resolver = w3.ens.resolver(namehash)
        return {
            'is_ens': True,
            'registered': resolver is not None,
            'owner': resolver.address if resolver else None
        }
    except Exception as e:
        print(f"ENS Check Error: {str(e)}")
        return {'is_ens': False}

def check_ssl(url):
    try:
        if not url.startswith('https://'):
            return {'valid': True, 'error_type': None}

        session = requests.Session()
        session.mount('https://', TLSAdapter())
        response = session.get(
            url,
            timeout=8,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Accept-Language': 'en-US,en;q=0.9'
            },
            allow_redirects=True,
            stream=False
        )
        return {'valid': True, 'error_type': None}
    except requests.exceptions.ConnectionError as e:
        error_msg = "Domain resolution failed" if "getaddrinfo failed" in str(e) else "Connection error"
        return {'valid': False, 'error_type': error_msg}
    except Exception as e:
        return {'valid': False, 'error_type': str(e)}

def check_domain_age(domain):
    try:
        info = whois.whois(domain)
        
        # Handle non-existent domains
        if not info.domain_name:
            return {'age': None, 'exists': False}
            
        created = info.creation_date
        
        # Handle null/undefined creation dates
        if not created:
            return {'age': None, 'exists': True}
            
        # Handle list-type creation dates
        if isinstance(created, list):
            created = created[0]
            
        # Verify datetime type
        if not isinstance(created, datetime):
            return {'age': None, 'exists': True}
            
        return {
            'age': (datetime.now() - created).days,
            'exists': True
        }
        
    except PywhoisError as e:
        # Specific handling for domain not found
        return {'age': None, 'exists': False}
    except Exception as e:
        print(f"Domain Age Error: {str(e)[:120]}...")  # Truncate long errors
        return {'age': None, 'exists': None}

def check_safe_browsing(url):
    try:
        response = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": GOOGLE_API_KEY},
            json={
                "client": {"clientId": "phishguard", "clientVersion": "5.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=8
        )
        if response.status_code != 200:
            print(f"Safe Browsing API Error: {response.text}")
        return bool(response.json().get('matches'))
    except Exception as e:
        print(f"Safe Browsing Error: {str(e)}")
        return False

def analyze_url(url):
    try:
        parsed = tldextract.extract(url)
        registered_domain = parsed.registered_domain.lower()

         
        # Web3: Check ENS domain
        ens_check = check_ens_registration(registered_domain)
        
        if any(registered_domain == d.lower() for d in TRUSTED_DOMAINS):
            return {"risk_score": 0, "flags": ["Trusted domain"], "analyzed_url": url}

        risk_score = 0
        flags = []

         # Web3 Risk Factors
        if ens_check.get('registered'):
            flags.append("Valid ENS Domain ✅")
            risk_score -= 20  # Trust bonus
        elif is_ens_domain(registered_domain):
            flags.append("Invalid ENS Domain ⚠️")
            risk_score += 60
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            ssl_future = executor.submit(check_ssl, url)
            domain_future = executor.submit(check_domain_age, registered_domain)
            google_future = executor.submit(check_safe_browsing, url)

            # Brand impersonation
            brand_match = next(
                (b for b in BRAND_DOMAINS 
                 if b in parsed.domain.lower() or 
                    b in registered_domain.replace('-','')), 
                None
            )
            if brand_match:
                if not any(registered_domain.endswith(d) for d in BRAND_DOMAINS[brand_match]):
                    risk_score += 80
                    flags.append(f"Brand Impersonation: {brand_match.upper()}")
                    if parsed.suffix not in ['com', 'net', 'org']:
                        risk_score += 40
                        flags.append("Suspicious TLD")

            # Typosquatting detection
            if is_typosquatting(registered_domain):
                risk_score += 60
                flags.append("Typosquatting Patterns Detected")

            # Domain age analysis
            domain_data = domain_future.result(timeout=10)
            if domain_data['exists'] is False:
                risk_score += 70
                flags.append("Unregistered Domain")
            elif domain_data['age'] is not None:
                if domain_data['age'] < 90:
                    risk_score += 50
                    flags.append("New Domain (<90 days)")
                if domain_data['age'] < 7:
                    risk_score += 40
                    flags.append("Very New Domain (<7 days)")
            elif domain_data['exists'] is True:
                flags.append("Suspicious Registration Data")

            # SSL verification
            ssl_result = ssl_future.result(timeout=6)
            if not ssl_result['valid']:
                risk_score += 40
                if "Domain resolution failed" in ssl_result['error_type']:
                    flags.append("Unreachable domain (DNS failure)")
                else:
                    flags.append(f"SSL/Connection Error: {ssl_result['error_type']}")

            # Safe Browsing check
            if google_future.result(timeout=10):
                risk_score += 100
                flags.append("Google: Known Phishing Site")

            # URL structure analysis
            if len(parsed.subdomain.split('.')) > 2:
                risk_score += 30
                flags.append("Complex Subdomain Structure")

             # Add Web3-specific flags
            if re.search(r'0x[a-fA-F0-9]{40}', url):
                risk_score += 50
                flags.append("Contains Wallet Address Pattern ⚠️")


        final_score = min(150, risk_score)
        return {
            "risk_score": final_score,
            "flags": flags,
            "analyzed_url": url
        }

    except Exception as e:
        print(f"Analysis Critical Error: {str(e)}")
        return {
            "risk_score": 100,
            "flags": ["Security verification failed"],
            "analyzed_url": url
        }

@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request"}), 400
            
        if not isinstance(data['url'], str) or len(data['url']) > 2048:
            return jsonify({"error": "Invalid URL format"}), 400
            
        return jsonify(analyze_url(data['url']))
        
    except Exception as e:
        print(f"Endpoint Error: {str(e)}")
        return jsonify({"error": "Server processing error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
