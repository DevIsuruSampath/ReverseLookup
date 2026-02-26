#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Advanced Python Version
Find all domains using advanced Python techniques
"""

import argparse
import socket
import dns.resolver
import dns.reversename
import subprocess
import sys
import re
import os
import ssl
import urllib.request
import urllib.parse
import urllib.error
import json
import hashlib
from typing import Optional, Tuple, Set, List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class ReverseLookup:
    """Advanced reverse IP lookup using Python techniques"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Initialize DNS resolver
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
        except dns.resolver.NoResolverConfiguration:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']

    def add_domain(self, domain: str) -> bool:
        """Add domain if not duplicate"""
        if domain and '.' in domain and len(domain) > 3:
            clean = domain.lower().strip()
            # Filter out arpa, aws, and invalid patterns
            skip_patterns = ['.in-addr.arpa', '.ip6.arpa', '.compute.amazonaws.com',
                           '.amazonaws.com', '.cloudfront.net', '.elasticbeanstalk.com',
                           '.aws.amazon.com', '.ec2.internal', '.privatelink']
            if not any(pattern in clean for pattern in skip_patterns):
                if clean not in self.domains:
                    self.domains.add(clean)
                    return True
        return False

    # ==================== DNS PTR Lookup ====================

    def dns_ptr_lookup(self, ip: str) -> int:
        """DNS PTR record lookup"""
        count = 0
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(reverse_name, 'PTR')
            
            for rdata in answers:
                domain = str(rdata).rstrip('.')
                if self.add_domain(domain):
                    count += 1
                    print(f"  [DNS-PTR] {domain}")
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print(f"  [DNS-PTR] No PTR record found")
        except Exception as e:
            print(f"  [DNS-PTR] Error: {e}")
        
        return count

    # ==================== Certificate Transparency (crt.sh) ====================

    def crtsh_lookup(self, ip: str) -> int:
        """Certificate Transparency lookup via crt.sh"""
        count = 0
        
        # Get base domain from PTR
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr = str(ptr_answers[0]).rstrip('.')
                # Extract base domain
                parts = ptr.split('.')
                if len(parts) >= 2:
                    base_domains.append('.'.join(parts[-2:]))
                    base_domains.append('.'.join(parts[-3:]))  # Try 3 parts too
        except:
            pass
        
        if not base_domains:
            return 0
        
        for base_domain in base_domains[:2]:  # Limit to avoid too many requests
            url = f"https://crt.sh/?q=%.25252.{base_domain}&output=json"
            
            try:
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = json.loads(response.read().decode('utf-8'))

                for cert in data:
                    domain = cert['name_value'].strip()
                    # Handle wildcards
                    domain = domain.lstrip('*.')
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [crt.sh] {domain}")

            except Exception as e:
                print(f"  [crt.sh] Error: {e}")
        
        return count

    # ==================== HTTP Header Scraping ====================

    def http_header_lookup(self, ip: str) -> int:
        """HTTP header scraping for domains"""
        count = 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                base_domain = str(ptr_answers[0]).rstrip('.')
        except:
            pass
        
        if not base_domain or 'amazonaws.com' in base_domain:
            return 0
        
        # Common subdomains to test
        subdomains = ['www', 'api', 'app', 'm', 'mobile', 'blog', 'shop']
        
        for sub in subdomains:
            test_domain = f"{sub}.{base_domain}"
            try:
                url = f"http://{test_domain}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    headers = dict(response.headers)
                    
                    # Check various headers for domains
                    domain_patterns = [
                        headers.get('Server', ''),
                        headers.get('X-Powered-By', ''),
                        headers.get('X-Server', ''),
                        headers.get('Via', ''),
                        headers.get('X-Forwarded-For', ''),
                        response.getheader('Location', ''),
                    ]
                    
                    domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                    for text in domain_patterns:
                        if text:
                            matches = re.findall(domain_pattern, text)
                            for domain in matches:
                                if self.add_domain(domain):
                                    count += 1
                                    print(f"  [HTTP-Header] {domain}")

            except Exception:
                pass
        
        return count

    # ==================== SSL/TLS Certificate Parsing ====================

    def ssl_cert_lookup(self, ip: str, port: int = 443) -> int:
        """SSL/TLS certificate parsing for domains"""
        count = 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                base_domain = str(ptr_answers[0]).rstrip('.')
        except:
            pass
        
        if not base_domain or 'amazonaws.com' in base_domain:
            return 0
        
        # Common subdomains to test
        subdomains = ['www', 'api', 'app', 'm', 'mail', 'secure']
        
        for sub in subdomains:
            test_domain = f"{sub}.{base_domain}"
            try:
                # Try to get SSL certificate
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=test_domain) as secure_sock:
                        cert = secure_sock.getpeercert()
                        
                        # Extract domains from certificate
                        if 'subject' in cert:
                            subject = cert['subject']
                            for item in subject:
                                for key, value in item:
                                    if key == 'commonName':
                                        if self.add_domain(value):
                                            count += 1
                                            print(f"  [SSL-Cert] {value}")
                        
                        # Extract SAN (Subject Alternative Names)
                        if 'subjectAltName' in cert:
                            san = cert['subjectAltName']
                            if san:
                                for alt_name in san.split(','):
                                    alt_name = alt_name.strip()
                                    if alt_name.startswith('DNS:'):
                                        domain = alt_name[4:].strip('"\'')
                                        if self.add_domain(domain):
                                            count += 1
                                            print(f"  [SSL-Cert] {domain}")

            except Exception:
                pass
        
        return count

    # ==================== Advanced Subdomain Brute Force ====================

    def advanced_bruteforce(self, ip: str) -> int:
        """Advanced subdomain bruteforce with wordlist"""
        count = 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                base_domain = str(ptr_answers[0]).rstrip('.')
        except:
            pass
        
        if not base_domain or 'amazonaws.com' in base_domain:
            return 0
        
        # Advanced subdomain wordlist
        subdomains = [
            # Common
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'production',
            'app', 'apps', 'mobile', 'm', 'w', 'wap', 'web',
            # Infrastructure
            'cdn', 'static', 'assets', 'img', 'images', 'video', 'media', 'upload', 'download',
            'files', 'docs', 'wiki', 'help', 'support', 'forum', 'community', 'blog',
            # Services
            'shop', 'store', 'checkout', 'cart', 'order', 'payment', 'billing', 'account',
            'login', 'signin', 'signup', 'register', 'auth', 'oauth', 'sso',
            # Tech
            'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'smtp', 'pop', 'imap', 'exchange',
            'db', 'database', 'cache', 'redis', 'mongo', 'elastic', 'search',
            # DevOps
            'jenkins', 'gitlab', 'git', 'svn', 'nexus', 'artifactory', 'sonar', 'bamboo',
            'k8s', 'kubernetes', 'docker', 'registry', 'helm', 'argo', 'consul', 'vault',
            # Monitoring
            'grafana', 'prometheus', 'kibana', 'elastic', 'log', 'metrics', 'monitor',
            # Security
            'ssl', 'secure', 'vpn', 'firewall', 'gateway', 'proxy', 'lb', 'loadbalancer',
            # Business
            'hr', 'crm', 'erp', 'mail', 'email', 'webmail', 'calendar', 'drive',
            # Location/Region
            'us', 'eu', 'asia', 'na', 'sa', 'emea', 'apac', 'latam',
            'us-east', 'us-west', 'eu-west', 'eu-central', 'ap-south', 'ap-east',
            # Platform
            'ios', 'android', 'api-v1', 'api-v2', 'api-v3', 'v1', 'v2', 'v3', 'v4',
            'beta', 'alpha', 'preview', 'demo', 'sandbox', 'staging', 'qa', 'u',
            # Popular
            'portal', 'dashboard', 'panel', 'console', 'admin', 'manage', 'manage',
            'client', 'customers', 'partners', 'suppliers', 'vendors',
            # Social
            'share', 'connect', 'social', 'community', 'network',
            # Media
            'stream', 'video', 'audio', 'music', 'radio', 'tv', 'live',
        ]
        
        # Check subdomains in parallel
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.check_subdomain, f"{sub}.{base_domain}") for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    count += 1
        
        return count

    def check_subdomain(self, domain: str) -> Optional[str]:
        """Check if subdomain exists"""
        try:
            self.resolver.resolve(domain, 'A')
            if self.add_domain(domain):
                print(f"  [Brute-Force] {domain}")
                return domain
        except:
            pass
        return None

    # ==================== CNAME Chain Traversal ====================

    def cname_chain_lookup(self, ip: str) -> int:
        """Follow CNAME chain to find related domains"""
        count = 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                base_domain = str(ptr_answers[0]).rstrip('.')
        except:
            pass
        
        if not base_domain or 'amazonaws.com' in base_domain:
            return 0
        
        # Common CNAME sources
        cnames = ['www', 'm', 'mobile', 'app', 'api', 'cdn', 'web']
        
        for cname in cnames:
            test_domain = f"{cname}.{base_domain}"
            try:
                # Follow CNAME chain (up to 3 hops)
                current = test_domain
                for _ in range(3):
                    try:
                        answers = self.resolver.resolve(current, 'CNAME')
                        for rdata in answers:
                            cname_target = rdata.target.to_text().rstrip('.')
                            if self.add_domain(cname_target):
                                count += 1
                                print(f"  [CNAME-Chain] {cname_target}")
                            current = cname_target
                    except:
                        break

            except Exception:
                pass
        
        return count

    # ==================== DNS Records (MX, NS, TXT, SRV) ====================

    def dns_record_lookup(self, ip: str, record_type: str, source_name: str) -> int:
        """Generic DNS record lookup"""
        count = 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                base_domain = str(ptr_answers[0]).rstrip('.')
        except:
            pass
        
        if not base_domain:
            return 0
        
        try:
            answers = self.resolver.resolve(base_domain, record_type)
            
            for rdata in answers:
                domain = None
                if hasattr(rdata, 'exchange'):
                    domain = rdata.exchange.to_text().rstrip('.')
                elif hasattr(rdata, 'target'):
                    domain = rdata.target.to_text().rstrip('.')
                elif hasattr(rdata, 'to_text'):
                    domain = rdata.to_text().rstrip('.')
                
                if domain and self.add_domain(domain):
                    count += 1
                    print(f"  [DNS-{source_name}] {domain}")
                    
        except Exception as e:
            pass  # Silently skip if no records
        
        return count

    # ==================== WHOIS Lookup ====================

    def whois_lookup(self, ip: str) -> int:
        """WHOIS lookup for domain information"""
        count = 0
        
        if not self.check_command('whois'):
            print(f"  [WHOIS] Tool not found (install: apt install whois)")
            return 0
        
        try:
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(domain_pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [WHOIS] {domain}")
                        
        except Exception as e:
            print(f"  [WHOIS] Error: {e}")
        
        return count

    # ==================== DNSrecon (Kali Tool) ====================

    def dnsrecon_lookup(self, ip: str) -> int:
        """DNSrecon - DNS reconnaissance tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('dnsrecon'):
            return 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                base_domain = str(ptr_answers[0]).rstrip('.')
        except:
            pass
        
        if not base_domain or 'amazonaws.com' in base_domain:
            return 0
        
        try:
            output_file = f"/tmp/dnsrecon_{ip.replace('.', '_')}.json"
            result = subprocess.run(
                ['dnsrecon', '-d', base_domain, '-j', output_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                    
                    if 'dnskey' in data:
                        for record in data['dnskey']:
                            if 'name' in record:
                                domain = record['name'].rstrip('.')
                                if self.add_domain(domain):
                                    count += 1
                                    print(f"  [DNSrecon] {domain}")
                    
                    if 'zonetransfer' in data:
                        for record in data['zonetransfer']:
                            if 'name' in record:
                                domain = record['name'].rstrip('.')
                                if self.add_domain(domain):
                                    count += 1
                                    print(f"  [DNSrecon] {domain}")
                    
                    os.remove(output_file)
                except:
                    pass
                        
        except Exception as e:
            pass
        
        return count

    # ==================== Helper Functions ====================

    def check_command(self, command: str) -> bool:
        """Check if a command is available"""
        try:
            subprocess.run(
                ['which', command],
                capture_output=True,
                timeout=5
            )
            return True
        except:
            return False

    def save_output(self):
        """Save results to file"""
        if not self.output_file:
            return

        sorted_domains = sorted(self.domains)

        if self.output_format == 'txt':
            with open(self.output_file, 'w') as f:
                f.write('\n'.join(sorted_domains))
                f.write(f'\n\nTotal: {len(sorted_domains)} domains')

        elif self.output_format == 'json':
            with open(self.output_file, 'w') as f:
                json.dump({
                    'domains': sorted_domains,
                    'total': len(sorted_domains)
                }, f, indent=2)

        elif self.output_format == 'csv':
            with open(self.output_file, 'w') as f:
                f.write('domain\n')
                for domain in sorted_domains:
                    f.write(f'{domain}\n')

        print(f"\n✅ Saved {len(sorted_domains)} domains to {self.output_file}")

    def lookup(self, ip: str):
        """Perform advanced reverse IP lookup"""
        print(f"\n🔍 Advanced Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('crt.sh', self.crtsh_lookup),
            ('HTTP-Header', self.http_header_lookup),
            ('SSL-Cert', self.ssl_cert_lookup),
            ('CNAME-Chain', self.cname_chain_lookup),
            ('Advanced-Brute', self.advanced_bruteforce),
            ('DNS-MX', lambda x: self.dns_record_lookup(x, 'MX', 'MX')),
            ('DNS-NS', lambda x: self.dns_record_lookup(x, 'NS', 'NS')),
            ('DNS-SRV', lambda x: self.dns_record_lookup(x, 'SRV', 'SRV')),
            ('WHOIS', self.whois_lookup),
            ('DNSrecon', self.dnsrecon_lookup),
        ]

        total_found = 0
        for name, method in sources:
            try:
                found = method(ip)
                total_found += found
            except Exception as e:
                print(f"  [{name}] Error: {e}")

        elapsed = time.time() - start_time

        print(f"\n{'='*50}")
        print(f"📊 Results:")
        print(f"   Total unique domains: {len(self.domains)}")
        print(f"   Time elapsed: {elapsed:.2f}s")

        # Save output
        if self.output_file:
            self.save_output()

        return list(self.domains)


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^[0-9a-fA-F:]+$'

    if re.match(ipv4_pattern, ip):
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    elif re.match(ipv6_pattern, ip):
        return True
    return False


def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    if not domain:
        return False
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))


def resolve_domain(domain: str) -> Tuple[bool, str]:
    """Resolve domain to IP address"""
    try:
        ip = socket.gethostbyname(domain)
        return True, ip
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Reverse IP Lookup - Uses Python techniques',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Advanced Python Techniques:
  Certificate Transparency (crt.sh) - SSL certificate logs
  HTTP Header Scraping - Extract domains from headers
  SSL/TLS Certificate Parsing - Extract domains from certs
  CNAME Chain Traversal - Follow CNAME redirects
  Advanced Subdomain Bruteforce - 150+ subdomains
  DNS Records - PTR, MX, NS, SRV
  WHOIS Lookup - Domain information
  DNSrecon - Kali tool (if available)

Note: No external APIs or data sources required.
Works on Linux, Kali, Termux, macOS, Windows.
        """
    )

    parser.add_argument('target', help='IP address or domain to lookup')
    parser.add_argument('--output', '-o', type=str,
                        help='Output file path (default: stdout)')
    parser.add_argument('--format', '-f', choices=['txt', 'json', 'csv'],
                        default='txt', help='Output format (default: txt)')

    args = parser.parse_args()

    # Determine if target is IP or domain
    target_ip = args.target
    is_domain = False

    if validate_ip(args.target):
        target_ip = args.target
        print(f"📍 Target: {args.target} (IP address)")
    elif validate_domain(args.target):
        is_domain = True
        print(f"🔗 Resolving domain: {args.target}")

        success, result = resolve_domain(args.target)
        if not success:
            print(f"❌ {result}")
            sys.exit(1)

        target_ip = result
        print(f"✅ Resolved to: {target_ip}")
    else:
        print(f"❌ Invalid IP address or domain: {args.target}")
        sys.exit(1)

    # Perform lookup
    lookup = ReverseLookup(args.output, args.format)
    domains = lookup.lookup(target_ip)

    # Print summary
    if not args.output or args.format == 'txt':
        print(f"\n{'='*50}")
        print(f"🔢 Domains found: {len(domains)}")
        if len(domains) <= 100:
            print(f"\n{chr(10).join(sorted(domains))}")


if __name__ == '__main__':
    main()
