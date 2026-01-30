"""
Advanced Subdomain Scanner
Real-world production-grade subdomain discovery
Uses Certificate Transparency, DNS enumeration, and brute force
"""

import socket
import dns.resolver
import dns.zone
import dns.query
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from urllib.parse import urlparse
from datetime import datetime
import json
import re

class SubdomainScanner:
    """Advanced subdomain discovery tool"""
    
    def __init__(self):
        # Comprehensive subdomain wordlist - Real-world production-grade
        self.common_subdomains = [
            # Core infrastructure
            'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'ww1', 'ww2', 'ww3',
            'mail', 'mail1', 'mail2', 'mail3', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
            'ftp', 'ftp1', 'ftp2', 'ftps', 'sftp', 'files', 'file', 'upload', 'uploads',
            'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns', 'dns1', 'dns2', 'dns3',
            'mx', 'mx1', 'mx2', 'mx3', 'mx4', 'mx5', 'smtp1', 'smtp2', 'smtp3',
            
            # Common services
            'api', 'api1', 'api2', 'api-v1', 'api-v2', 'api-v3', 'rest', 'graphql',
            'cdn', 'cdn1', 'cdn2', 'static', 'assets', 'images', 'img', 'media',
            'admin', 'administrator', 'management', 'manager', 'console', 'dashboard',
            'portal', 'login', 'auth', 'sso', 'oauth', 'iam', 'identity',
            'vpn', 'remote', 'gateway', 'gw', 'proxy', 'firewall', 'fw',
            
            # Development & Testing
            'dev', 'develop', 'development', 'devel', 'developer',
            'test', 'testing', 'test1', 'test2', 'test3', 'qa', 'qat',
            'stage', 'staging', 'stg', 'pre-prod', 'preprod', 'uat',
            'demo', 'sandbox', 'lab', 'playground', 'experimental',
            'beta', 'alpha', 'preview', 'canary', 'edge',
            
            # Production environments
            'prod', 'production', 'live', 'app', 'application',
            'web', 'web1', 'web2', 'web3', 'web-app', 'webapp',
            'server', 'server1', 'server2', 'srv', 'srv1', 'srv2',
            
            # Database & Storage
            'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb',
            'redis', 'elastic', 'elasticsearch', 'sql', 'mssql', 'oracle',
            'backup', 'backups', 'bak', 'archive', 'archives', 'store', 'storage',
            
            # Content Management
            'cms', 'blog', 'news', 'forum', 'forums', 'community', 'social',
            'wiki', 'docs', 'documentation', 'doc', 'help', 'support', 'kb',
            'shop', 'store', 'ecommerce', 'cart', 'checkout', 'payment', 'pay',
            
            # Mobile & Regional
            'm', 'mobile', 'wap', 'app-mobile', 'android', 'ios',
            'us', 'uk', 'eu', 'asia', 'de', 'fr', 'es', 'it', 'jp', 'cn', 'in',
            'en', 'english', 'www-en', 'www-de', 'www-fr',
            
            # Cloud & Infrastructure
            'cloud', 'aws', 'azure', 'gcp', 'k8s', 'kubernetes', 'docker',
            'jenkins', 'ci', 'cd', 'pipeline', 'build', 'deploy', 'release',
            'monitoring', 'monitor', 'metrics', 'logs', 'logging', 'analytics',
            'status', 'health', 'ping', 'heartbeat',
            
            # Email & Communication
            'autodiscover', 'autoconfig', 'cpanel', 'whm', 'webdisk',
            'exchange', 'owa', 'outlook', 'calendar', 'contacts',
            'chat', 'messenger', 'im', 'irc', 'slack', 'teams',
            
            # Security & Compliance
            'secure', 'ssl', 'tls', 'cert', 'certificate', 'certs',
            'security', 'sec', 'vault', 'secrets', 'keys',
            'compliance', 'audit', 'logs', 'siem',
            
            # Social & Marketing
            'blog', 'press', 'media', 'news', 'newsletter', 'subscribe',
            'marketing', 'promo', 'promotions', 'campaign', 'campaigns',
            'social', 'facebook', 'twitter', 'linkedin', 'instagram',
            
            # Business Functions
            'crm', 'erp', 'hr', 'finance', 'accounting', 'billing',
            'sales', 'customer', 'clients', 'partners', 'vendor', 'suppliers',
            'invoice', 'orders', 'inventory', 'warehouse',
            
            # Education specific
            'lms', 'moodle', 'blackboard', 'canvas', 'elearning', 'mooc',
            'student', 'students', 'faculty', 'staff', 'alumni',
            'library', 'libkoha', 'lib', 'books', 'digital-library',
            'admission', 'admissions', 'apply', 'application', 'placement',
            'hostel', 'residence', 'campus', 'academics', 'academic',
            'exam', 'examination', 'exams', 'result', 'results', 'grade', 'grades',
            'timetable', 'schedule', 'course', 'courses', 'syllabus',
            'research', 'journal', 'publications', 'conference', 'workshop',
            'sports', 'cultural', 'events', 'fest', 'techfest',
            
            # Department codes
            'cse', 'cs', 'ece', 'eee', 'mech', 'mechanical', 'civil', 'it',
            'eie', 'ice', 'ai', 'ml', 'ds', 'csbs', 'chem', 'chemistry',
            'bio', 'biology', 'physics', 'maths', 'mathematics', 'english',
            'mba', 'mca', 'bba', 'bca', 'btech', 'mtech',
            
            # Common prefixes/patterns
            'my', 'old', 'new', 'latest', 'current', 'legacy', 'v1', 'v2', 'v3',
            'internal', 'external', 'public', 'private', 'intranet', 'extranet',
            'git', 'svn', 'repo', 'repository', 'code', 'source',
            'download', 'downloads', 'get', 'put', 'post',
            'search', 'find', 'lookup', 'query',
            'stats', 'statistics', 'reports', 'reporting', 'dashboard',
            'video', 'videos', 'stream', 'streaming', 'live',
            'service', 'services', 'microservice', 'microservices',
            'data', 'big-data', 'datastore', 'datalake',
            'jobs', 'careers', 'hiring', 'recruitment',
            'events', 'calendar', 'booking', 'reservation',
            'feedback', 'survey', 'poll', 'vote',
            'notification', 'notifications', 'alerts', 'notify',
            
            # Technical infrastructure
            'loadbalancer', 'lb', 'balancer', 'edge', 'edge-server',
            'cache', 'memcache', 'memcached', 'varnish',
            'queue', 'mq', 'rabbitmq', 'kafka', 'pubsub',
            'worker', 'workers', 'cron', 'scheduler', 'batch',
            'registry', 'harbor', 'nexus', 'artifactory',
            'grafana', 'prometheus', 'elk', 'kibana', 'splunk',
            'nagios', 'zabbix', 'icinga', 'sensu',
            
            # Common numbered variants
            'app1', 'app2', 'app3', 'web-1', 'web-2', 'web-3',
            'node1', 'node2', 'node3', 'host1', 'host2', 'host3',
            
            # GitHub/GitLab style
            'pages', 'raw', 'gist', 'wiki', 'issues', 'projects',
            'ci-cd', 'actions', 'workflows', 'packages',
            
            # Misc common
            'about', 'contact', 'info', 'information', 'privacy',
            'terms', 'legal', 'policy', 'cookies', 'gdpr',
            'sitemap', 'robots', 'humans', 'ads', 'advertising',
            'track', 'tracking', 'pixel', 'tag', 'tags',
            'click', 'redirect', 'link', 'short', 'url',
            
            # Additional expanded list
            'status', 'health', 'heartbeat', 'check', 'checks',
            'config', 'configuration', 'settings', 'env', 'environment',
            'secret', 'secrets', 'key', 'keys', 'password', 'passwords',
            'token', 'tokens', 'auth', 'authorize', 'authenticate',
            'mirror', 'mirrors', 'backup-site', 'alternate', 'fallback',
            'staging-api', 'test-api', 'api-test', 'api-staging', 'sandbox-api',
            'ws', 'websocket', 'socket', 'realtime', 'events',
            'webhook', 'webhooks', 'callback', 'callbacks', 'hooks',
            'form', 'forms', 'survey', 'surveys', 'feedback',
            'report', 'reports', 'analytics', 'metrics', 'insights',
            'trace', 'traces', 'debug', 'profile', 'profiling',
            'feature', 'features', 'flag', 'flags', 'toggle', 'toggles',
            'experiment', 'experiments', 'ab-test', 'abt', 'cohort',
            'segment', 'segments', 'audience', 'audiences', 'cohorts',
            'rule', 'rules', 'policy', 'policies', 'governance',
            'trigger', 'triggers', 'action', 'actions', 'reaction',
            'template', 'templates', 'theme', 'themes', 'skin',
            'brand', 'branding', 'assets', 'static', 'cdn',
            'region', 'regions', 'zone', 'zones', 'location',
            'us-east', 'us-west', 'eu-central', 'ap-south', 'ap-southeast',
            'shard', 'shards', 'partition', 'partitions', 'replica',
            'primary', 'secondary', 'tertiary', 'backup', 'standby',
            'hot', 'warm', 'cold', 'archive', 'glacier',
            'stream', 'streams', 'flow', 'flows', 'pipeline',
            'batch', 'batches', 'job', 'jobs', 'task', 'tasks',
            'queue', 'queues', 'broker', 'brokers', 'bus',
            'event', 'events', 'message', 'messages', 'notification',
            'alert', 'alerts', 'warning', 'warnings', 'critical',
            'incident', 'incidents', 'issue', 'issues', 'ticket',
            'problem', 'problems', 'issue-tracker', 'bug-tracker', 'tracking',
            'sprint', 'sprints', 'milestone', 'milestones', 'release',
            'version', 'versions', 'build', 'builds', 'artifact',
            'package', 'packages', 'bundle', 'bundles', 'distribution',
            'installer', 'setup', 'init', 'bootstrap', 'initialize',
            'migration', 'migrations', 'upgrade', 'upgrades', 'patch',
            'rollback', 'rollbacks', 'revert', 'reverts', 'undo',
            'sync', 'syncs', 'synchronize', 'synchronization', 'replicate',
            'copy', 'copies', 'clone', 'clones', 'duplicate',
            'merge', 'merges', 'branch', 'branches', 'trunk',
            'tag', 'tags', 'commit', 'commits', 'history',
            'blame', 'annotate', 'diff', 'diffs', 'patch',
            'pull', 'merge-request', 'pr', 'issue-pr', 'discussion',
            'review', 'reviews', 'approve', 'approval', 'verify',
            'sign', 'signature', 'verify', 'verification', 'validate',
            'encode', 'decode', 'encrypt', 'decrypt', 'hash',
            'checksum', 'checksums', 'integrity', 'verify-integrity', 'validate-hash',
        ]
        
        # DNS resolver with optimized settings
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']  # Use Google & Cloudflare DNS
        
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
            # Try DNS resolution with multiple record types
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
            else:
                # Try CNAME records
                try:
                    answers = self.resolver.resolve(full_domain, 'CNAME')
                    if answers:
                        # CNAME exists, try to get IP from target
                        target = str(answers[0].target).rstrip('.')
                        ip = self.get_ip_address(target)
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
        except:
            pass
        
        return None
    
    def get_certificate_subdomains(self, domain):
        """Extract subdomains from SSL certificate (Certificate Transparency)"""
        subdomains = set()
        
        try:
            # Method 1: crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=15, verify=True)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split by newlines (multiple domains in one cert)
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        
                        # Remove wildcards
                        if name.startswith('*.'):
                            name = name[2:]
                        
                        # Only keep subdomains of target domain
                        if name.endswith(domain) and name != domain:
                            # Extract subdomain part
                            subdomain = name.replace(f".{domain}", "")
                            # Only direct subdomains (no nested like api.v1.domain.com)
                            if subdomain and '.' not in subdomain:
                                subdomains.add(subdomain)
                            # Also add nested subdomains but extract first level
                            elif subdomain and '.' in subdomain:
                                first_level = subdomain.split('.')[-1]
                                if first_level:
                                    subdomains.add(first_level)
                
                print(f"✓ Certificate Transparency: Found {len(subdomains)} unique subdomains")
        except Exception as e:
            print(f"⚠ Certificate scan error: {e}")
        
        # Method 2: Try common certificate patterns
        try:
            common_cert_patterns = ['www', 'mail', 'autodiscover', 'autoconfig', 'cpanel', 
                                   'webmail', 'smtp', 'pop', 'imap', 'ftp']
            for pattern in common_cert_patterns:
                if pattern not in subdomains:
                    subdomains.add(pattern)
        except:
            pass
        
        return subdomains
    
    def try_dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer (AXFR) - rarely works but worth trying"""
        subdomains = set()
        
        try:
            # Get nameservers for the domain
            ns_records = self.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                try:
                    # Try zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain, timeout=5))
                    if zone:
                        for name in zone.nodes.keys():
                            subdomain = str(name)
                            if subdomain != '@' and subdomain != domain:
                                subdomains.add(subdomain)
                        print(f"✓ Zone transfer successful from {ns_name}!")
                except:
                    pass  # Zone transfer blocked (expected)
        except:
            pass
        
        return subdomains
    
    def get_dns_records(self, domain):
        """Get additional subdomains from DNS records"""
        subdomains = set()
        
        record_types = ['MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    record_str = str(rdata).lower()
                    # Extract potential subdomains from records
                    if domain in record_str:
                        parts = record_str.split('.')
                        for i, part in enumerate(parts):
                            if domain.split('.')[0] in '.'.join(parts[i:]):
                                potential_subdomain = '.'.join(parts[:i])
                                if potential_subdomain and '.' not in potential_subdomain:
                                    subdomains.add(potential_subdomain)
            except:
                pass
        
        return subdomains
    
    def bruteforce_subdomains(self, base_domain, wordlist=None, max_workers=100):
        """Brute force subdomain discovery with parallel processing"""
        if wordlist is None:
            # Use full wordlist for comprehensive scanning
            wordlist = self.common_subdomains
        
        found_subdomains = []
        
        print(f"🔍 Brute forcing {len(wordlist)} potential subdomains with {max_workers} threads...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.check_subdomain_exists, subdomain, base_domain): subdomain
                for subdomain in wordlist
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(f"Progress: {completed}/{len(wordlist)} checked...")
                
                try:
                    result = future.result()
                    if result:
                        found_subdomains.append(result)
                        print(f"✓ Found: {result['full_domain']} ({result['ip']})")
                except Exception as e:
                    pass  # Silent fail for faster scanning
        
        return found_subdomains
    
    def scan_domain(self, url_or_domain, use_certificate=True, use_bruteforce=True, use_dns=True):
        """
        Complete subdomain scan using multiple techniques
        
        Args:
            url_or_domain: URL or domain to scan
            use_certificate: Use certificate transparency logs
            use_bruteforce: Use brute force with wordlist
            use_dns: Use DNS enumeration techniques
        
        Returns:
            dict: Scan results
        """
        start_time = time.time()
        
        # Extract base domain
        base_domain = self.extract_domain(url_or_domain)
        print(f"\n🎯 Target Domain: {base_domain}")
        print("=" * 70)
        
        all_subdomains = {}
        subdomain_set = set()
        
        # Method 1: DNS Records Analysis
        if use_dns:
            print("\n🔍 Analyzing DNS Records...")
            try:
                dns_subdomains = self.get_dns_records(base_domain)
                subdomain_set.update(dns_subdomains)
                print(f"✓ Found {len(dns_subdomains)} potential subdomains from DNS records")
            except Exception as e:
                print(f"⚠ DNS analysis: {e}")
            
            # Try zone transfer (rarely works)
            print("🔐 Attempting DNS Zone Transfer...")
            try:
                zone_subdomains = self.try_dns_zone_transfer(base_domain)
                if zone_subdomains:
                    subdomain_set.update(zone_subdomains)
                    print(f"✓ Zone transfer found {len(zone_subdomains)} subdomains!")
                else:
                    print("⚠ Zone transfer blocked (expected)")
            except Exception as e:
                print(f"⚠ Zone transfer blocked")
        
        # Method 2: Certificate Transparency Logs
        if use_certificate:
            print("\n📜 Scanning Certificate Transparency Logs...")
            try:
                cert_subdomains = self.get_certificate_subdomains(base_domain)
                subdomain_set.update(cert_subdomains)
                print(f"✓ Found {len(cert_subdomains)} unique subdomains from SSL certificates")
            except Exception as e:
                print(f"⚠ Certificate scan: {e}")
        
        # Method 3: Brute Force with Comprehensive Wordlist
        if use_bruteforce:
            print("\n💪 Brute Force DNS Enumeration...")
            try:
                bruteforce_results = self.bruteforce_subdomains(base_domain)
                
                for result in bruteforce_results:
                    subdomain = result['subdomain']
                    subdomain_set.add(subdomain)
                    all_subdomains[subdomain] = result
                
                print(f"✓ Brute force completed: {len(bruteforce_results)} active subdomains")
            except Exception as e:
                print(f"⚠ Brute force error: {e}")
        
        # Resolve all discovered subdomains
        print(f"\n🔍 Resolving {len(subdomain_set)} discovered subdomains...")
        unresolved_count = 0
        for subdomain in subdomain_set:
            if subdomain not in all_subdomains:
                result = self.check_subdomain_exists(subdomain, base_domain)
                if result:
                    all_subdomains[subdomain] = result
                else:
                    unresolved_count += 1
        
        if unresolved_count > 0:
            print(f"⚠ {unresolved_count} subdomains discovered but not currently resolving")
        
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
        
        print("\n" + "=" * 70)
        print(f"✅ SCAN COMPLETE!")
        print(f"   🎯 Target: {base_domain}")
        print(f"   📊 Total Subdomains Found: {results['subdomain_count']}")
        print(f"   🌐 Unique IP Addresses: {results['unique_ips']}")
        print(f"   🔥 Most Used IP: {results['most_used_ip']} ({results['most_used_ip_count']}x)")
        print(f"   🛡️  Cloudflare Protected: {results['cloudflare_count']}")
        print(f"   ⏱️  Total Scan Time: {results['scan_time']}s")
        print("=" * 70)
        
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
