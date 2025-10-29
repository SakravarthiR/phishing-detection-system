"""
main detection stuff - this is where everything works.

"""

import re
import pandas as pd
import joblib
from typing import Dict, Tuple, Optional
import os
import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
import sys
import pickle
import io
import warnings
import gc  # Garbage collection for memory optimization

# gotta fix sklearn before we import it
import sklearn
from sklearn import tree, ensemble

# monkey patch stuff at the top to remove monotonic_cst from old models
original_dt_setstate = tree.DecisionTreeClassifier.__setstate__
original_rf_setstate = ensemble.RandomForestClassifier.__setstate__

def patched_dt_setstate(self, state):
    """remove monotonic_cst from the old model states"""
    if isinstance(state, dict):
        state.pop('monotonic_cst', None)
        state.pop('monotonic', None)
    return original_dt_setstate(self, state)

def patched_rf_setstate(self, state):
    """remove monotonic_cst from the old model states"""
    if isinstance(state, dict):
        state.pop('monotonic_cst', None)
        state.pop('monotonic', None)
    return original_rf_setstate(self, state)

tree.DecisionTreeClassifier.__setstate__ = patched_dt_setstate
ensemble.RandomForestClassifier.__setstate__ = patched_rf_setstate

print("[+] sklearn __setstate__ patches applied at import")


def check_website_live(url: str, timeout: int = 5) -> dict:
    """
    check if a website is actually working and get info about it.
    
    this does real HTTP requests so like dont spam it too much.
    gives back stuff like status code, SSL cert, redirects and stuff.
    """
    result = {
        'is_reachable': False,
        'status_code': None,
        'response_time': None,
        'has_ssl': False,
        'ssl_valid': False,
        'ssl_issuer': None,
        'ssl_expiry': None,
        'redirects': 0,
        'final_url': None,
        'content_type': None,
        'server': None,
        'suspicious_formats': [],
        'error': None
    }
    
    try:
        # just add http if its not there
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        start_time = datetime.now()
        
        # make request and follow redirects
        response = requests.get(
            url, 
            timeout=timeout,
            allow_redirects=True,
            verify=False,  # yeah i know we probably shouldnt do this but we need to catch bad SSL
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        
        # get the basic stuff
        result['is_reachable'] = True
        result['status_code'] = response.status_code
        result['response_time'] = round(response_time, 2)
        result['final_url'] = response.url
        result['redirects'] = len(response.history)
        
        # get the headers info
        result['content_type'] = response.headers.get('Content-Type', 'Unknown')
        result['server'] = response.headers.get('Server', 'Unknown')
        
        # check for weird stuff in the response
        if response.status_code >= 400:
            result['suspicious_formats'].append(f'HTTP Error {response.status_code}')
        
        if result['redirects'] > 3:
            result['suspicious_formats'].append(f'Too many redirects ({result["redirects"]}) - thats sus')
        
        # if its HTTPS check the SSL cert
        if url.startswith('https://'):
            result['has_ssl'] = True
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                port = parsed.port or 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl_valid'] = True
                        result['ssl_issuer'] = dict(x[0] for x in cert['issuer'])['commonName']
                        
                        # parse the expiry date
                        expiry_str = cert['notAfter']
                        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        result['ssl_expiry'] = expiry_date.strftime('%Y-%m-%d')
                        
                        # check if the cert expired
                        if expiry_date < datetime.now():
                            result['suspicious_formats'].append('SSL certificate is expired')
                            result['ssl_valid'] = False
                            
            except ssl.SSLError as e:
                result['ssl_valid'] = False
                result['suspicious_formats'].append(f'Bad SSL: {str(e)[:50]}')
            except Exception as e:
                result['ssl_valid'] = False
                result['suspicious_formats'].append('SSL check didnt work')
        
        # check content type stuff
        content_type = result['content_type'].lower()
        if 'text/html' not in content_type and 'application/xhtml' not in content_type:
            if response.status_code == 200:
                result['suspicious_formats'].append(f'Weird content type: {content_type}')
        
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout - website is slow or not responding'
        result['suspicious_formats'].append('Timeout')
    except requests.exceptions.ConnectionError:
        result['error'] = 'Cant connect - website might be down'
        result['suspicious_formats'].append('Connection failed')
    except requests.exceptions.TooManyRedirects:
        result['error'] = 'way too many redirects'
        result['suspicious_formats'].append('Redirect loop detected')
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request error: {str(e)[:100]}'
        result['suspicious_formats'].append('Request failed')
    except Exception as e:
        result['error'] = f'Unexpected error: {str(e)[:100]}'
    
    return result


def extract_subdomain_info(url: str) -> dict:
    url_lower = url.lower()
    
    # Extract domain from URL
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url_lower)
    
    if not domain_match:
        return {
            'subdomain_count': 0,
            'subdomains': [],
            'full_domain': ''
        }
    
    full_domain = domain_match.group(1)
    domain_parts = full_domain.split('.')
    
    # Calculate subdomain count
    # Typical domain: example.com (2 parts) -> 0 subdomains
    # With subdomain: sub.example.com (3 parts) -> 1 subdomain
    # Multiple: a.b.example.com (4 parts) -> 2 subdomains
    
    subdomain_count = max(0, len(domain_parts) - 2)
    subdomains = domain_parts[:-2] if subdomain_count > 0 else []
    
    return {
        'subdomain_count': subdomain_count,
        'subdomains': subdomains,
        'full_domain': full_domain
    }


def extract_features(url: str) -> pd.DataFrame:
    """
    pull out lexical features from URLs for phishing detection.
    uses regex patterns to find features accuratly.
    
    Args:
        url: the URL string to look at
        
    Returns:
        a pandas DataFrame with one row of extracted features
        
    Features extracted:
        - url_length: total number of characters
        - num_dots: how many '.' are there
        - num_hyphens: how many '-' are there
        - num_digits: count of numbers
        - has_ip: 1 if URL has IPv4 address
        - has_ipv6: 1 if URL has IPv6 address
        - has_suspicious_keyword: has phishing related words
        - is_https: uses HTTPS or not
        - num_subdomains: how many subdomains
        - entropy: randomness measure
        - has_port: has weird port number
        - has_double_slash: has '//' in path (bad sign)
        - has_at_symbol: has '@' (obfuscation)
        - has_shortening_service: uses URL shortener
        - domain_length: lengh of domain
        - path_length: lengh of path
        - has_hex_chars: has hex encoding
        - suspicious_tld: uses suspicious TLD
        - digit_letter_ratio: digits vs letters
    """
    from collections import Counter
    import math
    
    features = {}
    url_lower = url.lower()
    
    # basic length stuff
    features['url_length'] = len(url)
    
    # regex patterns to find things accurately
    
    # 1. check for IPv4 addresses (making sure numbers are 0-255)
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    features['has_ip'] = 1 if re.search(ipv4_pattern, url) else 0
    
    # 2. check for IPv6 addresses (simplified version)
    ipv6_pattern = r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})'
    features['has_ipv6'] = 1 if re.search(ipv6_pattern, url) else 0
    
    # 3. count special characters
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_question'] = url.count('?')
    features['num_ampersand'] = url.count('&')
    features['num_equals'] = url.count('=')
    features['num_percent'] = url.count('%')
    
    # 4. count digits and figure out digit to letter ratio
    features['num_digits'] = sum(c.isdigit() for c in url)
    num_letters = sum(c.isalpha() for c in url)
    features['digit_letter_ratio'] = features['num_digits'] / max(num_letters, 1)
    
    # 5. check if @ symbol is there (used for obfuscation)
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 6. Advanced suspicious keyword detection (case-insensitive with word boundaries)
    suspicious_keywords = [
        'login', 'verify', 'account', 'update', 'secure', 'banking', 'signin', 
        'confirm', 'suspend', 'restrict', 'alert', 'unlock', 'validate', 
        'credential', 'password', 'paypal', 'ebay', 'amazon', 'apple', 
        'microsoft', 'wallet', 'billing', 'payment', 'webscr'
    ]
    features['has_suspicious_keyword'] = 1 if any(kw in url_lower for kw in suspicious_keywords) else 0
    
    # 7. Count occurrences of suspicious keywords
    features['suspicious_keyword_count'] = sum(url_lower.count(kw) for kw in suspicious_keywords)
    
    # 8. Protocol detection (HTTPS vs HTTP)
    features['is_https'] = 1 if url_lower.startswith('https://') else 0
    
    # 9. Extract and analyze domain components
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url_lower)
    if domain_match:
        domain = domain_match.group(1)
        features['domain_length'] = len(domain)
        
        # Count subdomains (more accurate)
        domain_parts = domain.split('.')
        # Typical domain has 2 parts (domain.tld), anything more is subdomains
        features['num_subdomains'] = max(0, len(domain_parts) - 2)
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', '.zip']
        features['suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
        
        # Domain has only digits (highly suspicious)
        features['domain_all_digits'] = 1 if domain.replace('.', '').isdigit() else 0
    else:
        features['domain_length'] = 0
        features['num_subdomains'] = 0
        features['suspicious_tld'] = 0
        features['domain_all_digits'] = 0
    
    # 10. Extract path and query components
    path_match = re.search(r'(?:https?://[^/]+)(/[^?#]*)?', url)
    if path_match and path_match.group(1):
        path = path_match.group(1)
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
    else:
        features['path_length'] = 0
        features['path_depth'] = 0
    
    # 11. Port detection (non-standard ports are suspicious)
    port_pattern = r':(\d{2,5})(?:/|$)'
    port_match = re.search(port_pattern, url)
    if port_match:
        port = int(port_match.group(1))
        # Standard ports: 80 (HTTP), 443 (HTTPS), 8080 (HTTP alt)
        features['has_port'] = 1 if port not in [80, 443] else 0
        features['port_number'] = port
    else:
        features['has_port'] = 0
        features['port_number'] = 0
    
    # 12. Check for double slash in path (path confusion attack)
    if '//' in url:
        # Remove protocol part, then check for remaining //
        after_protocol = url.split('://', 1)[-1] if '://' in url else url
        features['has_double_slash_in_path'] = 1 if '//' in after_protocol else 0
    else:
        features['has_double_slash_in_path'] = 0
    
    # 13. URL shortening services detection
    shortening_services = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
        'buff.ly', 'adf.ly', 'bit.do', 'short.io', 'rebrand.ly', 'cutt.ly'
    ]
    features['has_shortening_service'] = 1 if any(service in url_lower for service in shortening_services) else 0
    
    # 14. Hexadecimal/URL encoding detection (obfuscation)
    hex_pattern = r'%[0-9a-fA-F]{2}'
    hex_matches = re.findall(hex_pattern, url)
    features['has_hex_chars'] = 1 if hex_matches else 0
    features['hex_char_count'] = len(hex_matches)
    
    # 15. Punycode detection (internationalized domain names - IDN homograph attack)
    features['has_punycode'] = 1 if 'xn--' in url_lower else 0
    
    # 16. Shannon Entropy (measure of randomness - higher = more random/suspicious)
    if len(url) > 0:
        counter = Counter(url)
        entropy = 0.0
        for count in counter.values():
            probability = count / len(url)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        features['entropy'] = entropy
    else:
        features['entropy'] = 0.0
    
    # 17. Domain entropy (randomness in domain name only)
    if domain_match:
        domain = domain_match.group(1)
        if len(domain) > 0:
            counter = Counter(domain)
            domain_entropy = 0.0
            for count in counter.values():
                probability = count / len(domain)
                if probability > 0:
                    domain_entropy -= probability * math.log2(probability)
            features['domain_entropy'] = domain_entropy
        else:
            features['domain_entropy'] = 0.0
    else:
        features['domain_entropy'] = 0.0
    
    # 18. Check for excessive subdomain hyphens (typosquatting technique)
    features['has_excessive_hyphens'] = 1 if features['num_hyphens'] > 3 else 0
    
    # 19. Check for brand name typosquatting patterns
    brand_names = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'instagram']
    typo_pattern = r'|'.join([f'{brand}[0-9-]' for brand in brand_names])
    features['has_brand_typo'] = 1 if re.search(typo_pattern, url_lower) else 0
    
    # 20. Query string analysis
    query_match = re.search(r'\?(.+)', url)
    if query_match:
        query = query_match.group(1)
        features['query_length'] = len(query)
        features['num_query_params'] = query.count('&') + 1
    else:
        features['query_length'] = 0
        features['num_query_params'] = 0
    
    # Return as DataFrame (single row)
    return pd.DataFrame([features])


def fix_model_attributes(model):
    """
    Fix monotonic_cst attribute on model and all nested estimators.
    This handles old models that were trained with scikit-learn 1.3.2 but are loaded
    with newer versions like 1.7.2.
    
    Instead of deleting the attribute, we set it to None (the expected default value).
    """
    try:
        # For RandomForest, fix all individual trees
        if hasattr(model, 'estimators_'):
            for tree in model.estimators_:
                if tree is not None:
                    # Set monotonic_cst to None if missing - this is what new sklearn expects
                    if not hasattr(tree, 'monotonic_cst'):
                        tree.monotonic_cst = None
        
        print(f"[+] Model attributes fixed - set monotonic_cst to None on all trees")
        return model
    except Exception as e:
        print(f"[!] Warning: could not fully fix model attributes: {e}")
        return model


def load_model(model_path: str = 'phish_model.pkl'):
    """
    Load the trained phishing detection model from disk.
    sklearn __setstate__ patches are applied at module import.
    Additional fixing of model instances after loading.
    
    Args:
        model_path: Path to the saved model file
        
    Returns:
        The loaded model object, or None if loading fails
    """
    try:
        if not os.path.exists(model_path):
            print(f"[-] Model file not found: {model_path}")
            return None
        
        # Load with joblib (sklearn patches already applied)
        model = joblib.load(model_path)
        print(f"[+] Model loaded successfully from {model_path}")
        
        # Fix attributes on the loaded model instance
        model = fix_model_attributes(model)
        
        return model
        
    except Exception as e:
        print(f"[-] Error loading model: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def perform_advanced_threat_detection(url: str, timeout: int = 5) -> Dict:
    import socket as socket_module
    import ssl as ssl_module
    import re as regex_module
    import gc
    
    scan_results = {
        'server_info': {},
        'ssl_info': {},
        'dns_info': {},
        'http_headers': {},
        'technologies': [],
        'vulnerabilities': [],
        'risk_indicators': [],
        'scan_score': 0.5
    }
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or 'localhost'
        
        # MEMORY OPTIMIZATION: Set strict timeout and limits
        timeout = min(timeout, 5)  # Max 5 seconds
        max_response_size = 10 * 1024 * 1024  # Max 10MB
        
        # 1. SERVER FINGERPRINTING (with memory limits)
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(
                url, 
                timeout=timeout, 
                verify=False, 
                headers=headers,
                stream=True  # Stream response to save memory
            )
            
            # Limit response size
            if response.headers.get('content-length'):
                try:
                    size = int(response.headers.get('content-length', 0))
                    if size > max_response_size:
                        response.close()
                        del response
                        gc.collect()
                        return scan_results  # Skip large responses
                except:
                    pass
            
            # Collect HTTP headers only (not full body)
            scan_results['http_headers'] = dict(list(response.headers.items())[:10])  # Limit to 10 headers
            response.close()  # Close immediately
            
            # Server detection
            server_header = response.headers.get('Server', 'Unknown')
            scan_results['server_info']['server_header'] = server_header
            
            # Check for common vulnerable server versions
            vulnerable_servers = ['Apache/2.0', 'Apache/2.2', 'IIS/5.0', 'IIS/6.0']
            for vuln_server in vulnerable_servers:
                if vuln_server in server_header:
                    scan_results['vulnerabilities'].append(f"Outdated server version: {server_header}")
                    scan_results['risk_indicators'].append('Vulnerable server detected')
                    break  # Don't check all, limit iterations
            
            # Check for information disclosure headers
            bad_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
            for header in bad_headers:
                if header in response.headers:
                    scan_results['risk_indicators'].append(f"Information disclosure via {header}")
                    break  # Limit risk indicators
            
            # 2. TECHNOLOGY DETECTION (limited patterns)
            tech_patterns = {
                'WordPress': r'wp-content|wp-includes|wordpress',
                'Joomla': r'joomla|components/com_',
                'Drupal': r'drupal|/sites/all/',
                'Magento': r'magento|/app/etc/',
                'PHP': r'\.php|x-powered-by.*php',
                'ASP.NET': r'\.aspx|x-powered-by.*asp',
                'Python Django': r'django|csrftoken',
                'Node.js': r'x-powered-by.*express|x-powered-by.*node',
                'Ruby on Rails': r'rails|rack\.|x-powered-by.*ruby',
                'Java': r'java|tomcat|jsp|\.jar'
            }
            
            page_content = response.text
            for tech_name, pattern in tech_patterns.items():
                if regex_module.search(pattern, page_content + ' ' + str(response.headers), regex_module.IGNORECASE):
                    scan_results['technologies'].append(tech_name)
            
            # 3. COMMON ADMIN PATHS (LIMITED TO 2 CHECKS FOR MEMORY EFFICIENCY)
            admin_paths = ['/admin', '/wp-admin']  # Reduced from 6 to 2 most common
            for admin_path in admin_paths:
                admin_url = url.rstrip('/') + admin_path
                try:
                    admin_response = requests.head(admin_url, timeout=1, verify=False)  # Reduced timeout
                    if admin_response.status_code < 400:
                        scan_results['risk_indicators'].append(f"Admin panel potentially exposed: {admin_path}")
                    admin_response.close()
                except:
                    pass
            
            # 4. BACKUP FILE DETECTION (LIMITED TO 2 CHECKS FOR MEMORY EFFICIENCY)
            backup_patterns = [
                url.rstrip('/') + '/backup.zip',
                url.rstrip('/') + '/backup.sql'
            ]  # Reduced from 4 to 2
            
            for backup_url in backup_patterns:
                try:
                    backup_response = requests.head(backup_url, timeout=1, verify=False)  # Reduced timeout
                    if backup_response.status_code < 400:
                        scan_results['risk_indicators'].append(f"Backup file potentially accessible: {backup_url}")
                    backup_response.close()
                except:
                    pass
            
        except Exception as e:
            print(f"[!] Server fingerprinting error: {e}")
        
        # 5. SSL/TLS CERTIFICATE ANALYSIS
        try:
            context = ssl_module.create_default_context()
            with socket_module.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        scan_results['ssl_info']['valid'] = True
                        scan_results['ssl_info']['subject'] = str(cert.get('subject', []))
                        scan_results['ssl_info']['issuer'] = str(cert.get('issuer', []))
                        
                        # Check for self-signed or suspicious certificates
                        issuer_str = str(cert.get('issuer', ''))
                        if 'self' in issuer_str.lower():
                            scan_results['risk_indicators'].append('Self-signed SSL certificate detected')
                    
                    # Get SSL version
                    try:
                        ssl_version = ssock.version()
                        scan_results['ssl_info']['protocol'] = ssl_version
                        if 'SSLv2' in ssl_version or 'SSLv3' in ssl_version:
                            scan_results['risk_indicators'].append(f"Outdated SSL protocol: {ssl_version}")
                    except:
                        pass
        except Exception as e:
            print(f"[!] SSL analysis error: {e}")
        
        # 6. DNS RESOLUTION
        try:
            ip_address = socket_module.gethostbyname(hostname)
            scan_results['dns_info']['ip_address'] = ip_address
            
            # Check for suspicious IP patterns
            if ip_address.startswith('192.168') or ip_address.startswith('10.'):
                scan_results['risk_indicators'].append('Private IP address (possibly phishing redirect)')
            
            # Check for known malicious IPs (simplified check)
            if ip_address.startswith('127.') or ip_address.startswith('0.'):
                scan_results['risk_indicators'].append('Loopback or invalid IP address')
        except Exception as e:
            print(f"[!] DNS resolution error: {e}")
        
        # 7. CALCULATE SCAN SCORE
        # Start at 0.5 (neutral)
        scan_score = 0.5
        
        # Add points for each risk indicator
        scan_score += (len(scan_results['risk_indicators']) * 0.05)
        
        # Subtract points for legitimate technologies
        if len(scan_results['technologies']) > 0:
            scan_score -= 0.05
        
        # Check SSL validity
        if scan_results['ssl_info'].get('valid'):
            scan_score -= 0.10
        
        # Cap score
        scan_results['scan_score'] = max(0.0, min(1.0, scan_score))
        
        return scan_results
        
    except Exception as e:
        print(f"[!] Advanced threat detection error: {e}")
        scan_results['scan_score'] = 0.5  # Default to neutral if scan fails
        return scan_results



def analyze_website_content(url: str, timeout: int = 5) -> Dict:

    analysis = {
        'has_login_form': False,
        'has_external_form': False,
        'has_meta_refresh': False,
        'has_hidden_inputs': False,
        'suspicious_scripts': 0,
        'external_links_count': 0,
        'forms_targeting_external': 0,
        'domain_mismatches': 0,
        'phishing_indicators': 0,
        'legitimacy_indicators': 0,
        'content_score': 0.0,
        'ssl_valid': False,
        'has_security_headers': False,
        'redirect_count': 0,
        'external_forms': 0,
        'suspicious_domains': 0,
        'trust_badges': 0,
        'scan_details': {}
    }
    
    try:
        import re as regex_module
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # MEMORY OPTIMIZATION: Limit timeout and response size
        timeout = min(timeout, 5)  # Max 5 seconds
        max_response_size = 5 * 1024 * 1024  # Max 5MB for content analysis
        
        # Perform the request with full SSL context
        response = requests.get(url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
        
        if response.status_code != 200:
            analysis['content_score'] = 0.35
            analysis['scan_details']['status_error'] = f"HTTP {response.status_code}"
            response.close()
            return analysis
        
        # MEMORY OPTIMIZATION: Check response size before loading
        if response.headers.get('content-length'):
            try:
                size = int(response.headers.get('content-length', 0))
                if size > max_response_size:
                    analysis['content_score'] = 0.35
                    analysis['scan_details']['status_error'] = f"Response too large: {size} bytes"
                    response.close()
                    del response
                    gc.collect()
                    return analysis
            except:
                pass
        
        # MEMORY OPTIMIZATION: Capture all needed headers BEFORE processing content
        response_headers = dict(response.headers)
        response_history = response.history
        
        html_content = response.text[:max_response_size]  # Limit to first 5MB
        html_lower = html_content.lower()
        response.close()  # Close response immediately after reading
        del response  # Release response object
        gc.collect()  # Garbage collection
        
        # Extract domain from URL
        parsed_url = urlparse(url)
        main_domain = parsed_url.netloc.replace('www.', '')
        
        # ===== SECTION 1: SSL/TLS CERTIFICATE ANALYSIS =====
        try:
            # Check SSL certificate validity
            import ssl as ssl_module
            context = ssl_module.create_default_context()
            with socket.create_connection((parsed_url.hostname or 'localhost', 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        analysis['ssl_valid'] = True
                        analysis['legitimacy_indicators'] += 2
        except Exception:
            if url.startswith('https'):
                analysis['phishing_indicators'] += 1  # HTTPS without valid cert is suspicious
        
        # ===== SECTION 2: SECURITY HEADERS ANALYSIS =====
        security_headers = [
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'content-security-policy',
            'x-xss-protection'
        ]
        found_security_headers = sum(1 for header in security_headers if header in [h.lower() for h in response_headers.keys()])
        if found_security_headers > 0:
            analysis['has_security_headers'] = True
            analysis['legitimacy_indicators'] += found_security_headers
        else:
            analysis['phishing_indicators'] += 1
        
        # ===== SECTION 3: REDIRECT CHAIN ANALYSIS =====
        analysis['redirect_count'] = len(response_history)
        if analysis['redirect_count'] > 2:
            analysis['phishing_indicators'] += 1  # Multiple redirects suspicious
        
        # ===== SECTION 4: FORM ANALYSIS (DEEP SCAN) =====
        forms = regex_module.findall(r'<form[^>]*>.*?</form>', html_lower, regex_module.DOTALL)
        if forms:
            for form in forms[:3]:  # Analyze first 3 forms
                # Check for password fields
                if 'type="password"' in form or "type='password'" in form or 'password' in form:
                    analysis['has_login_form'] = True
                    analysis['phishing_indicators'] += 1
                    
                    # Analyze form action
                    action_match = regex_module.search(r'action=["\']?([^"\'\s>]+)', form)
                    if action_match:
                        action_url = action_match.group(1)
                        if action_url.startswith('http'):
                            action_domain = urlparse(action_url).netloc.replace('www.', '')
                            if action_domain != main_domain:
                                analysis['has_external_form'] = True
                                analysis['phishing_indicators'] += 3  # Critical!
                                analysis['forms_targeting_external'] += 1
                                analysis['external_forms'] += 1
                
                # Count hidden fields
                hidden_count = len(regex_module.findall(r'type=["\']?hidden["\']?', form))
                if hidden_count > 5:
                    analysis['has_hidden_inputs'] = True
                    analysis['phishing_indicators'] += 1
        
        # ===== SECTION 5: JAVASCRIPT ANALYSIS =====
        js_patterns = {
            'keylogger': r'keylogger|keystroke|key.*log',
            'password_theft': r'steal.*password|harvest.*credential|capture.*password',
            'form_interception': r'formdata|form.*submit|onsubmit.*javascript',
            'obfuscation': r'eval\(|atob\(|String\.fromCharCode',
            'iframe_injection': r'createElement.*iframe|innerHTML.*iframe',
            'redirect_exploit': r'window\.location\.replace|window\.location\.href.*javascript',
            'cryptominer': r'crypto.*mine|hash.*calc|proof.*work'
        }
        
        suspicious_js_count = 0
        for pattern_name, pattern in js_patterns.items():
            if regex_module.search(pattern, html_lower):
                suspicious_js_count += 1
                analysis['suspicious_scripts'] += 1
                analysis['phishing_indicators'] += 1
        
        # ===== SECTION 6: EXTERNAL RESOURCES ANALYSIS =====
        external_scripts = regex_module.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html_lower)
        external_iframes = regex_module.findall(r'<iframe[^>]*src=["\']([^"\']+)["\']', html_lower)
        external_forms = regex_module.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html_lower)
        
        external_count = 0
        for resource in external_scripts + external_iframes + external_forms:
            if resource.startswith('http'):
                resource_domain = urlparse(resource).netloc.replace('www.', '')
                if resource_domain != main_domain:
                    external_count += 1
                    analysis['suspicious_domains'] += 1
        
        analysis['external_links_count'] = external_count
        if external_count > 5:
            analysis['phishing_indicators'] += 1
        
        # ===== SECTION 7: TRUST & LEGITIMACY INDICATORS =====
        legitimacy_patterns = {
            'privacy_policy': r'privacy\s*policy|privacy\s*statement',
            'terms_of_service': r'terms\s*of\s*service|terms\s*&\s*conditions|tos',
            'contact_info': r'contact\s*us|contact\s*information|email|phone',
            'about_page': r'about\s*us|about\s*company|company\s*profile',
            'copyright': r'copyright|&copy;|©.*20\d{2}',
            'company_name': r'inc\.|llc|corp\.|ltd\.|pvt',
            'certification': r'certified|iso\s*\d+|security\s*certified',
            'trust_seals': r'seal|badge|verified|trusted|secure',
            'social_links': r'facebook\.com|twitter\.com|linkedin\.com|instagram\.com'
        }
        
        for indicator_name, pattern in legitimacy_patterns.items():
            if regex_module.search(pattern, html_lower):
                analysis['legitimacy_indicators'] += 1
                if 'trust_seals' in indicator_name or 'certification' in indicator_name:
                    analysis['trust_badges'] += 1
        
        # ===== SECTION 8: SUSPICIOUS PATTERNS DETECTION =====
        suspicious_content = {
            'urgent_action': r'urgent|immediate\s*action|verify.*now|confirm.*now|expire',
            'account_lock': r'account.*lock|suspend|restrict|limit|unusual activity',
            'credential_request': r'enter.*password|confirm.*password|verify.*credential',
            'brand_impersonation': r'paypal|amazon|apple|microsoft|google|facebook|ebay|netflix',
            'phishing_keywords': r'verify account|update payment|confirm identity|unusual activity'
        }
        
        for pattern_name, pattern in suspicious_content.items():
            if regex_module.search(pattern, html_lower):
                analysis['phishing_indicators'] += 1
        
        # ===== SECTION 9: CALCULATE FINAL CONTENT SCORE =====
        # Start with neutral score
        content_score = 0.5
        
        # Apply phishing indicators (increase suspicion)
        content_score += (analysis['phishing_indicators'] * 0.08)  # Each indicator: +0.08
        
        # Apply legitimacy indicators (decrease suspicion)
        content_score -= (analysis['legitimacy_indicators'] * 0.05)  # Each indicator: -0.05
        
        # Bonus for security headers
        if analysis['has_security_headers']:
            content_score -= 0.15
        
        # Bonus for valid SSL
        if analysis['ssl_valid']:
            content_score -= 0.10
        
        # Penalty for external forms
        if analysis['external_forms'] > 0:
            content_score += 0.25
        
        # Cap at 0-1 range
        analysis['content_score'] = max(0.0, min(1.0, content_score))
        
        # Add scan summary
        analysis['scan_details'] = {
            'forms_found': len(forms),
            'external_scripts': len(external_scripts),
            'external_iframes': len(external_iframes),
            'js_threats': suspicious_js_count,
            'security_headers_found': found_security_headers,
            'trust_indicators': analysis['legitimacy_indicators'],
            'redirects': analysis['redirect_count']
        }
        
        return analysis
        
    except Exception as e:
        print(f"[!] Content analysis error: {str(e)}")
        # If we can't fetch content, assume moderate suspicion
        analysis['content_score'] = 0.45
        analysis['scan_details']['error'] = str(e)
        return analysis


def predict_url(url: str, model) -> Tuple[int, float, Dict]:

    if model is None:
        raise ValueError("Model is not loaded")
    
    # Extract features
    features_df = extract_features(url)
    features_dict = features_df.to_dict(orient='records')[0]

    # Make ML prediction
    prediction = model.predict(features_df)[0]

    # Get probability vector (confidence for each class)
    prob_vector = model.predict_proba(features_df)[0]
    # ml_phish_prob is model's probability for phishing class
    ml_phish_prob = float(prob_vector[1])
    # ml_legit_prob = float(prob_vector[0])
    
    # Clean up dataframe from memory
    del features_df
    gc.collect()
    
    # ===== ADVANCED RULE-BASED OVERRIDES =====
    # Sometimes the ML model is too trusting, so we add manual checks
    # If any of these trigger, we're pretty sure it's phishing
    phishing_score = 0
    url_lower = url.lower()
    
    # Critical red flags (these are REALLY bad)
    if features_dict.get('has_ip', 0) == 1:
        phishing_score += 50  # Nobody legit uses raw IP addresses lol
    
    if features_dict.get('has_at_symbol', 0) == 1:
        phishing_score += 40  # @ in URL? Yeah that's shady AF
    
    if features_dict.get('has_punycode', 0) == 1:
        phishing_score += 45  # IDN homograph attacks (evil unicode tricks)
    
    # Suspicious TLD + suspicious keywords = definitely up to something
    if features_dict.get('suspicious_tld', 0) == 1 and features_dict.get('has_suspicious_keyword', 0) == 1:
        phishing_score += 35
    
    # Free TLDs (.tk, .ml, etc) are sketchy, especially with security words
    free_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    security_keywords = ['verify', 'account', 'login', 'secure', 'update', 'confirm', 'suspend', 'alert']
    if any(url_lower.endswith(tld) for tld in free_tlds):
        if any(keyword in url_lower for keyword in security_keywords):
            phishing_score += 40  # Yeah this is basically always phishing
    
    # Other bad signs
    if features_dict.get('has_shortening_service', 0) == 1:
        phishing_score += 25  # URL shorteners hiding the real destination
    
    if features_dict.get('num_hyphens', 0) >= 3 and features_dict.get('has_suspicious_keyword', 0) == 1:
        phishing_score += 20  # pay-pal-verify-account.com type stuff
    
    if features_dict.get('suspicious_keyword_count', 0) >= 3:
        phishing_score += 25  # Way too many security buzzwords
    
    if features_dict.get('num_subdomains', 0) >= 4:
        phishing_score += 15  # login.secure.verify.paypal.evil.com vibes
    
    # URL encoding abuse (lots of %20 and stuff)
    if features_dict.get('has_hex_chars', 0) == 1 and features_dict.get('hex_char_count', 0) > 3:
        phishing_score += 15  # Trying to hide the actual URL
    
    # Long URLs with security keywords are usually hiding something
    if features_dict.get('url_length', 0) > 100 and features_dict.get('has_suspicious_keyword', 0) == 1:
        phishing_score += 10
    
    if features_dict.get('digit_letter_ratio', 0) > 0.4:
        phishing_score += 10  # URLs shouldn't have that many numbers
    
    # Brand impersonation check - this catches a LOT of phishing
    major_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'ebay', 'netflix', 'instagram']
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url_lower)
    if domain_match:
        domain = domain_match.group(1)
        # If the URL mentions PayPal but isn't actually paypal.com, that's sus
        for brand in major_brands:
            if brand in url_lower and not domain.endswith(f'{brand}.com'):
                phishing_score += 30  # Definitely trying to impersonate
                break
    
    # Final decision - override ML if our rules are confident enough
    if phishing_score >= 50:
        # Boost ML phishing probability
        ml_phish_prob = max(ml_phish_prob, min(0.95, 0.75 + (phishing_score / 200)))
    elif phishing_score >= 30 and prediction == 0:
        ml_phish_prob = max(ml_phish_prob, min(0.85, 0.65 + (phishing_score / 250)))

    # Content-based analysis (crawl the page and inspect forms/links/scripts)
    try:
        content_analysis = analyze_website_content(url)
    except Exception:
        content_analysis = {'content_score': 0.5}

    # Advanced deep scan for threat indicators
    try:
        threat_scan = perform_advanced_threat_detection(url)
        threat_score = threat_scan.get('scan_score', 0.5)
        risk_indicators = threat_scan.get('risk_indicators', [])
    except Exception:
        threat_scan = {}
        threat_score = 0.5
        risk_indicators = []

    # content_score is higher -> more suspicious (we designed it that way)
    content_suspicion = float(content_analysis.get('content_score', 0.5))

    # Normalize rule-based phishing score to 0-1 (assume max 100)
    rule_suspicion = max(0.0, min(1.0, phishing_score / 100.0))

    # Combine signals: weights tuned for balanced behaviour
    # ML (55%) + Content (25%) + Threat Detection (10%) + Rules (10%)
    w_ml = 0.55
    w_content = 0.25
    w_threat = 0.10
    w_rules = 0.10

    combined_phish_prob = (w_ml * ml_phish_prob) + (w_content * content_suspicion) + \
                         (w_threat * threat_score) + (w_rules * rule_suspicion)
    combined_phish_prob = max(0.0, min(1.0, combined_phish_prob))

    # Decide final label and confidence
    final_label = 1 if combined_phish_prob >= 0.5 else 0
    final_confidence = combined_phish_prob if final_label == 1 else 1.0 - combined_phish_prob

    # Merge content analysis into features for response/diagnostics
    features_dict.update({f'content_{k}': v for k, v in content_analysis.items()})
    
    # Add threat detection scan results
    features_dict.update({f'threat_{k}': v for k, v in threat_scan.items()})
    features_dict['threat_indicators'] = risk_indicators
    # Also include ML and combined probabilities for transparency
    features_dict['ml_phish_prob'] = round(ml_phish_prob, 4)
    features_dict['combined_phish_prob'] = round(combined_phish_prob, 4)

    # Clean up large objects before returning
    del content_analysis, threat_scan
    gc.collect()

    return int(final_label), float(final_confidence), features_dict


def get_top_feature(features_dict: Dict) -> str:
   
    reasons = []
    
    # Critical indicators (highest priority)
    if features_dict.get('has_ip', 0) == 1:
        reasons.append(" Uses IP address instead of domain name")
    
    if features_dict.get('has_ipv6', 0) == 1:
        reasons.append(" Uses IPv6 address")
    
    if features_dict.get('has_at_symbol', 0) == 1:
        reasons.append(" Contains '@' symbol (URL obfuscation)")
    
    if features_dict.get('has_punycode', 0) == 1:
        reasons.append(" Uses internationalized domain (possible homograph attack)")
    
    if features_dict.get('has_shortening_service', 0) == 1:
        reasons.append(" Uses URL shortening service (hides real destination)")
    
    if features_dict.get('has_brand_typo', 0) == 1:
        reasons.append(" Possible brand name typosquatting detected")
    
    if features_dict.get('domain_all_digits', 0) == 1:
        reasons.append(" Domain contains only numbers")
    
    # High priority indicators
    if features_dict.get('suspicious_keyword_count', 0) >= 2:
        reasons.append(f"Multiple suspicious keywords ({features_dict['suspicious_keyword_count']} found)")
    elif features_dict.get('has_suspicious_keyword', 0) == 1:
        reasons.append("Contains phishing-related keywords (login/verify/account)")
    
    if features_dict.get('suspicious_tld', 0) == 1:
        reasons.append("Uses suspicious top-level domain (.tk, .ml, .xyz, etc.)")
    
    if features_dict.get('has_port', 0) == 1:
        port = features_dict.get('port_number', 0)
        reasons.append(f"Non-standard port number ({port})")
    
    if features_dict.get('has_hex_chars', 0) == 1:
        count = features_dict.get('hex_char_count', 0)
        reasons.append(f"URL encoding detected ({count} hex characters - possible obfuscation)")
    
    if features_dict.get('has_double_slash_in_path', 0) == 1:
        reasons.append("Double slash in path (URL confusion technique)")
    
    # Medium priority indicators
    if features_dict.get('url_length', 0) > 100:
        reasons.append(f"Unusually long URL ({features_dict['url_length']} characters)")
    
    if features_dict.get('has_excessive_hyphens', 0) == 1:
        reasons.append(f"Excessive hyphens ({features_dict['num_hyphens']})")
    
    if features_dict.get('num_subdomains', 0) > 4:
        reasons.append(f"Too many subdomains ({features_dict['num_subdomains']})")
    
    if features_dict.get('domain_entropy', 0) > 4.0:
        reasons.append(f"Highly random domain name (entropy: {features_dict['domain_entropy']:.2f})")
    
    if features_dict.get('digit_letter_ratio', 0) > 0.3:
        reasons.append(f"High digit-to-letter ratio ({features_dict['digit_letter_ratio']:.2f})")
    
    # Lower priority indicators
    if features_dict.get('is_https', 0) == 0:
        reasons.append("Not using HTTPS (insecure)")
    
    if features_dict.get('path_depth', 0) > 5:
        reasons.append(f"Deep path structure ({features_dict['path_depth']} levels)")
    
    if features_dict.get('num_query_params', 0) > 10:
        reasons.append(f"Many query parameters ({features_dict['num_query_params']})")
    
    # Return top 3 most critical reasons
    if reasons:
        return " | ".join(reasons[:3])
    else:
        return "✓ URL appears normal based on lexical analysis"


def get_professional_risk_assessment(probability: float, label: int, features_dict: Dict) -> Dict:
    
    # Probability directly represents phishing risk - use it as-is
    # High probability = high phishing risk (dangerous)
    # Low probability = low phishing risk (safe)
    risk_percent = probability * 100
    
    # Define professional risk levels and messaging
    if risk_percent >= 95:
        return {
            'risk_level': 'CRITICAL',
            'risk_category': 'Extremely Dangerous',
            'confidence_percent': round(risk_percent, 2),
            'description': 'CRITICAL THREAT DETECTED - This site exhibits multiple characteristics of an advanced phishing or malware attack.',
            'details': 'The URL contains several confirmed phishing indicators including suspicious keywords, unusual domain structure, and high-risk content patterns. This domain is highly likely to be fraudulent.',
            'recommendation': 'DO NOT VISIT or enter credentials. Block this URL immediately.',
            'actions': ['Report to anti-phishing service', 'Block domain in firewall', 'Alert your security team'],
            'color': '#ff0000'  # Red
        }
    
    elif risk_percent >= 85:
        return {
            'risk_level': 'HIGH',
            'risk_category': 'Very High Risk',
            'confidence_percent': round(risk_percent, 2),
            'description': 'HIGH RISK - This site shows strong indicators of phishing activity.',
            'details': 'Multiple suspicious patterns detected including potential credential harvesting mechanisms, suspicious domain naming, and risky content. Exercise extreme caution.',
            'recommendation': 'Avoid visiting. Do not enter personal or financial information.',
            'actions': ['Verify with official source', 'Check with IT department', 'Use official app instead'],
            'color': '#ff6600'  # Orange
        }
    
    elif risk_percent >= 70:
        return {
            'risk_level': 'MEDIUM-HIGH',
            'risk_category': 'Suspicious',
            'confidence_percent': round(risk_percent, 2),
            'description': 'SUSPICIOUS - This site has characteristics that warrant caution.',
            'details': 'Several indicators suggest this may be a phishing attempt or fraudulent website. The domain structure, content patterns, or URL format contain warning signs.',
            'recommendation': 'Use with caution. Verify legitimacy before entering sensitive information.',
            'actions': ['Contact company directly using official channels', 'Look for security indicators', 'Check website SSL certificate'],
            'color': '#ffaa00'  # Dark orange
        }
    
    elif risk_percent >= 50:
        return {
            'risk_level': 'MEDIUM',
            'risk_category': 'Moderate Risk',
            'confidence_percent': round(risk_percent, 2),
            'description': 'MODERATE CAUTION - Some aspects of this site appear questionable.',
            'details': 'The site contains mixed signals. While not definitively phishing, certain characteristics differ from standard legitimate websites. Further verification recommended.',
            'recommendation': 'Proceed cautiously. Verify the site\'s legitimacy independently before sharing any data.',
            'actions': ['Go to official website directly', 'Verify URL in browser address bar', 'Check SSL certificate details'],
            'color': '#ffcc00'  # Yellow
        }
    
    elif risk_percent >= 30:
        return {
            'risk_level': 'LOW-MEDIUM',
            'risk_category': 'Low-Moderate Risk',
            'confidence_percent': round(risk_percent, 2),
            'description': 'LIKELY LEGITIMATE - This site appears mostly trustworthy with minor concerns.',
            'details': 'The site\'s characteristics are largely consistent with legitimate websites, though some minor indicators require verification.',
            'recommendation': 'Generally safe, but apply standard security practices.',
            'actions': ['Use strong, unique passwords', 'Enable two-factor authentication', 'Monitor account activity'],
            'color': '#99cc00'  # Light green
        }
    
    elif risk_percent >= 10:
        return {
            'risk_level': 'LOW',
            'risk_category': 'Very Low Risk',
            'confidence_percent': round(risk_percent, 2),
            'description': 'APPEARS LEGITIMATE - This site has strong indicators of being authentic.',
            'details': 'The domain structure, content patterns, and URL format are consistent with genuine, legitimate websites. Risk is minimal.',
            'recommendation': 'Safe to use. Standard security practices apply.',
            'actions': ['Use strong passwords', 'Keep software updated', 'Enable two-factor authentication'],
            'color': '#00cc00'  # Green
        }
    
    else:  # < 10%
        return {
            'risk_level': 'VERY LOW',
            'risk_category': 'Trusted',
            'confidence_percent': round(risk_percent, 2),
            'description': 'HIGHLY TRUSTED - This site is very likely legitimate.',
            'details': 'All analyzed characteristics strongly indicate an authentic, legitimate website. No phishing indicators detected.',
            'recommendation': 'Appears to be a legitimate site. Standard security practices apply.',
            'actions': ['Maintain good password hygiene', 'Use two-factor authentication where available'],
            'color': '#00aa00'  # Dark green
        }


if __name__ == "__main__":
    # Simple test
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login-verify-account",
        "https://secure-paypal-login-verify.suspicious-domain.com/update"
    ]
    
    print("Testing feature extraction:\n")
    for url in test_urls:
        print(f"URL: {url}")
        features = extract_features(url)
        print(features.to_dict(orient='records')[0])
        print("-" * 80)
