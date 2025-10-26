"""
Advanced Subdomain Scanner
Similar to c99.nl subdomain finder
Discovers subdomains through multiple techniques
"""

import socket
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from urllib.parse import urlparse
import ssl
import OpenSSL
from datetime import datetime
import json
import re

class SubdomainScanner:
    """Advanced subdomain discovery tool"""
    
    def __init__(self):
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
            'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
            'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
            'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover',
            'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay',
            'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
            'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor',
            'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw',
            'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload', 'nagios',
            'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet', 'test2',
            'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting', 'cloud',
            'de', 'gmail', 's', 'bbs', 'cs', 'ww', 'mrtg', 'git', 'image', 'members',
            'pda', 'mail3', 'bb', 'mailer', 'asp', 'asp2', 'catalog', 'preview', 'fr',
            'connect', 'www5', 'rs', 'im', 'devel', 'videos', 'www6', 'ms', 'newton',
            # Educational institution specific
            'edumate', 'library', 'libkoha', 'alumni', 'placement', 'admission', 'hostel',
            'erp', 'lms', 'student', 'faculty', 'research', 'journal', 'conference',
            'workshop', 'seminar', 'techfest', 'cultural', 'sports', 'nss', 'ncc',
            'coe', 'iqac', 'naac', 'aicte', 'ugc', 'digital', 'elearning', 'mooc',
            'classroom', 'examination', 'result', 'timetable', 'academic', 'department',
            # Department names
            'cse', 'ece', 'eee', 'mech', 'civil', 'it', 'eie', 'ice', 'ai', 'csbs',
            'chem', 'bio', 'physics', 'maths', 'english', 'mba', 'mca', 'bba', 'bca',
            # Common patterns
            'dev-', 'test-', 'stage-', 'prod-', 'qa-', 'uat-', 'demo-', 'sandbox-',
            'app-', 'api-', 'web-', 'mobile-', 'admin-', 'user-', 'client-', 'server-',
        ]
        
        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
    def extract_domain(self, url):
        """Extract base domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove port
            if ':' in domain:
                domain = domain.split(':')[0]
            
            return domain
        except:
            return url
    
    def get_ip_address(self, subdomain):
        """Get IP address for a subdomain"""
        try:
            ip = socket.gethostbyname(subdomain)
            return ip
        except:
            return None
    
    def check_cloudflare(self, ip):
        """Check if IP belongs to Cloudflare"""
        # Cloudflare IP ranges (simplified)
        cloudflare_ranges = [
            '173.245.', '103.21.', '103.22.', '103.31.', '141.101.', '108.162.',
            '190.93.', '188.114.', '197.234.', '198.41.', '162.158.', '104.16.',
            '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.',
            '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.',
            '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.',
        ]
        
        if ip:
            for cf_range in cloudflare_ranges:
                if ip.startswith(cf_range):
                    return True
        return False
    
    def check_subdomain_exists(self, subdomain, base_domain):
        """Check if subdomain exists and get details"""
        full_domain = f"{subdomain}.{base_domain}"
        
        try:
            # Try DNS resolution
            ip = self.get_ip_address(full_domain)
            
            if ip:
                is_cloudflare = self.check_cloudflare(ip)
                
                return {
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'ip': ip,
                    'cloudflare': 'on' if is_cloudflare else 'off',
                    'status': 'active'
                }
        except:
            pass
        
        return None
    
    def get_certificate_subdomains(self, domain):
        """Extract subdomains from SSL certificate (Certificate Transparency)"""
        subdomains = set()
        
        try:
            # Try to get certificate from crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split by newlines (multiple domains in one cert)
                    for name in name_value.split('\n'):
                        name = name.strip()
                        
                        # Remove wildcards
                        if name.startswith('*.'):
                            name = name[2:]
                        
                        # Only keep subdomains of target domain
                        if name.endswith(domain) and name != domain:
                            # Extract subdomain part
                            subdomain = name.replace(f".{domain}", "")
                            if subdomain and '.' not in subdomain:  # Only direct subdomains
                                subdomains.add(subdomain)
        except Exception as e:
            print(f"Certificate scan error: {e}")
        
        return subdomains
    
    def bruteforce_subdomains(self, base_domain, wordlist=None, max_workers=50):
        """Brute force subdomain discovery"""
        if wordlist is None:
            wordlist = self.common_subdomains
        
        found_subdomains = []
        
        print(f"🔍 Brute forcing {len(wordlist)} potential subdomains...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.check_subdomain_exists, subdomain, base_domain): subdomain
                for subdomain in wordlist
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"✓ Found: {result['full_domain']} ({result['ip']})")
        
        return found_subdomains
    
    def scan_domain(self, url_or_domain, use_certificate=True, use_bruteforce=True):
        """
        Complete subdomain scan
        
        Args:
            url_or_domain: URL or domain to scan
            use_certificate: Use certificate transparency logs
            use_bruteforce: Use brute force with wordlist
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        
        # Extract base domain
        base_domain = self.extract_domain(url_or_domain)
        print(f"\n🎯 Target Domain: {base_domain}")
        print("=" * 60)
        
        all_subdomains = {}
        subdomain_set = set()
        
        # Method 1: Certificate Transparency Logs
        if use_certificate:
            print("\n📜 Scanning Certificate Transparency Logs...")
            cert_subdomains = self.get_certificate_subdomains(base_domain)
            print(f"✓ Found {len(cert_subdomains)} subdomains from certificates")
            subdomain_set.update(cert_subdomains)
        
        # Method 2: Brute Force with Wordlist
        if use_bruteforce:
            print("\n💪 Brute Force Scanning...")
            bruteforce_results = self.bruteforce_subdomains(base_domain)
            
            for result in bruteforce_results:
                subdomain = result['subdomain']
                subdomain_set.add(subdomain)
                all_subdomains[subdomain] = result
        
        # Get details for subdomains found in cert logs but not in brute force
        print("\n🔍 Resolving additional subdomains from certificate logs...")
        for subdomain in subdomain_set:
            if subdomain not in all_subdomains:
                result = self.check_subdomain_exists(subdomain, base_domain)
                if result:
                    all_subdomains[subdomain] = result
                    print(f"✓ Resolved: {result['full_domain']} ({result['ip']})")
        
        # Calculate statistics
        ip_count = {}
        cloudflare_count = 0
        
        for subdomain_data in all_subdomains.values():
            ip = subdomain_data['ip']
            if ip:
                ip_count[ip] = ip_count.get(ip, 0) + 1
            
            if subdomain_data['cloudflare'] == 'on':
                cloudflare_count += 1
        
        # Find most used IP
        most_used_ip = None
        most_used_count = 0
        if ip_count:
            most_used_ip = max(ip_count.items(), key=lambda x: x[1])
            most_used_count = most_used_ip[1]
            most_used_ip = most_used_ip[0]
        
        scan_time = time.time() - start_time
        
        # Prepare results
        results = {
            'domain': base_domain,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'subdomain_count': len(all_subdomains),
            'scan_time': round(scan_time, 2),
            'most_used_ip': most_used_ip,
            'most_used_ip_count': most_used_count,
            'unique_ips': len(ip_count),
            'cloudflare_count': cloudflare_count,
            'subdomains': sorted(all_subdomains.values(), key=lambda x: x['subdomain']),
            'ip_statistics': dict(sorted(ip_count.items(), key=lambda x: x[1], reverse=True))
        }
        
        print("\n" + "=" * 60)
        print(f"✅ Scan Complete!")
        print(f"   Total Subdomains: {results['subdomain_count']}")
        print(f"   Unique IPs: {results['unique_ips']}")
        print(f"   Most Used IP: {results['most_used_ip']} ({results['most_used_ip_count']}x)")
        print(f"   Cloudflare Protected: {results['cloudflare_count']}")
        print(f"   Scan Time: {results['scan_time']}s")
        print("=" * 60)
        
        return results


# Test function
def test_scanner():
    """Test the scanner with example domain"""
    scanner = SubdomainScanner()
    
    # Test with a domain
    domain = "sairam.edu.in"
    results = scanner.scan_domain(domain)
    
    # Print results
    print("\n📊 Detailed Results:")
    print(json.dumps(results, indent=2))
    
    return results


if __name__ == "__main__":
    test_scanner()
