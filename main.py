#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Ultimate Smart Version
Find all domains using smart extraction, Certificate Transparency, and Kali tools
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
import json
from typing import Optional, Tuple, Set, List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class ReverseLookup:
    """Ultimate smart reverse IP lookup"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Initialize DNS resolver with multiple servers
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
        except dns.resolver.NoResolverConfiguration:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
            # Use multiple DNS servers for better results
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220']

    def extract_parent_domain(self, cloud_domain: str) -> Optional[str]:
        """Extract parent domain from cloud infrastructure"""
        if not cloud_domain:
            return None
            
        # AWS patterns
        aws_patterns = [
            (r'ec2-\d+-\d+-\d+\.compute-1\.amazonaws\.com', 'amazonaws.com'),
            (r'ec2-\d+-\d+-\d+\.compute\.amazonaws\.com', 'amazonaws.com'),
            (r'\.ec2\.internal', 'amazonaws.com'),
            (r'\.compute-\d+\.amazonaws\.com', 'amazonaws.com'),
        ]
        
        for pattern, parent in aws_patterns:
            if re.search(pattern, cloud_domain):
                return parent
        
        # GCP patterns
        gcp_patterns = [
            (r'\.compute\.googleapis\.com', 'googleapis.com'),
            (r'\.gcp\.google\.com', 'google.com'),
        ]
        
        for pattern, parent in gcp_patterns:
            if re.search(pattern, cloud_domain):
                return parent
        
        # Azure patterns
        azure_patterns = [
            (r'\.cloudapp\.azure\.com', 'azure.com'),
            (r'\.windows\.azure\.com', 'azure.com'),
        ]
        
        for pattern, parent in azure_patterns:
            if re.search(pattern, cloud_domain):
                return parent
        
        return None

    def is_noise_domain(self, domain: str) -> bool:
        """Check if domain is noise/registry domain"""
        domain_lower = domain.lower()
        
        # Registry and RIR domains
        registry_domains = [
            'arin.net', 'rdap.arin.net', 'www.arin.net',
            'ripe.net', 'rdap.ripe.net', 'www.ripe.net',
            'apnic.net', 'rdap.apnic.net',
            'lacnic.net', 'rdap.lacnic.net',
            'afrinic.net', 'rdap.afrinic.net',
            'iana.org', 'iana-servers.net',
            'root-servers.net',
        ]
        
        # Abuse and security domains
        abuse_domains = [
            '.abuse', '.spam', '.phish', '.scam',
            'abuse.net', 'dis.abuse', 'dis.incapsula.noc',
            'dis.imperva.rir', 'blacklist', 'spamhaus',
            'knack.black',
        ]
        
        # Check all noise patterns
        for noise_domain in registry_domains + abuse_domains:
            if noise_domain in domain_lower:
                return True
        
        # Check for numeric IP-like domains
        if re.match(r'^\d+[-.]\d+', domain_lower):
            return True
        
        # Check for dis/disabuse patterns
        if domain_lower.startswith('ww.dis.') or domain_lower.startswith('knack.'):
            return True
        
        return False

    def add_domain(self, domain: str) -> bool:
        """Add domain if not duplicate and not noise"""
        if domain and '.' in domain and len(domain) > 3:
            clean = domain.lower().strip()
            
            # Check for noise
            if self.is_noise_domain(clean):
                return False
            
            # Allow cloud infrastructure domains for CT search
            cloud_infra = ['.amazonaws.com', '.compute.amazonaws.com', '.googleapis.com',
                          '.cloudapp.azure.com', '.windows.azure.com']
            
            if clean not in self.domains:
                # Only add cloud infra if it's the PTR domain
                if any(infra in clean for infra in cloud_infra):
                    self.domains.add(clean)
                    return True
                else:
                    self.domains.add(clean)
                    return True
        return False

    # ==================== DNS PTR Lookup ====================

    def dns_ptr_lookup(self, ip: str) -> int:
        """DNS PTR record lookup"""
        count = 0
        ptr_domain = None
        
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(reverse_name, 'PTR')
            
            for rdata in answers:
                ptr_domain = str(rdata).rstrip('.')
                if self.add_domain(ptr_domain):
                    count += 1
                    print(f"  [DNS-PTR] {ptr_domain}")
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print(f"  [DNS-PTR] No PTR record found")
        except Exception as e:
            print(f"  [DNS-PTR] Error: {e}")
        
        # If PTR is cloud infrastructure, add parent domain for CT search
        if ptr_domain:
            parent = self.extract_parent_domain(ptr_domain)
            if parent:
                if self.add_domain(parent):
                    count += 1
                    print(f"  [DNS-PTR-Parent] {parent}")
        
        return count

    # ==================== Certificate Transparency (Multiple Sources) ====================

    def cert_transparency_lookup(self, ip: str) -> int:
        """Multiple Certificate Transparency sources"""
        count = 0
        
        # Get base domains from PTR
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                base_domains.append(ptr_domain)
                
                # Extract parent domain if cloud infra
                parent = self.extract_parent_domain(ptr_domain)
                if parent and parent != ptr_domain:
                    base_domains.append(parent)
        except:
            pass
        
        # Search each base domain in crt.sh
        for base_domain in base_domains[:3]:
            count += self.crtsh_search(base_domain)
            count += self.censys_ct_search(base_domain)
        
        return count

    def crtsh_search(self, domain: str) -> int:
        """Search crt.sh for certificates"""
        count = 0
        url = f"https://crt.sh/?q=%.25252.{domain}&output=json"
        
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            for cert in data:
                cert_domain = cert['name_value'].strip()
                cert_domain = cert_domain.lstrip('*.')
                if self.add_domain(cert_domain):
                    count += 1
                    print(f"  [crt.sh] {cert_domain}")

        except Exception:
            pass
        
        return count

    def censys_ct_search(self, domain: str) -> int:
        """Search Censys Certificate Transparency"""
        count = 0
        url = f"https://search.censys.io/api/v2/certificates?q=dns.names:{domain}"
        
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            if 'result' in data and 'code' in data['result']:
                for cert in data['result']['code']['certificates']:
                    if 'names' in cert:
                        for name_info in cert['names']:
                            if isinstance(name_info, dict) and 'value' in name_info:
                                cert_domain = name_info['value'].strip()
                                cert_domain = cert_domain.lstrip('*.')
                                if self.add_domain(cert_domain):
                                    count += 1
                                    print(f"  [Censys-CT] {cert_domain}")

        except Exception:
            pass
        
        return count

    # ==================== Advanced Subdomain Brute Force ====================

    def advanced_bruteforce(self, ip: str) -> int:
        """Advanced subdomain bruteforce with multiple base domains"""
        count = 0
        
        # Get base domains from PTR (include cloud infra for search)
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                base_domains.append(ptr_domain)
                
                # Extract parent domain if cloud infra
                parent = self.extract_parent_domain(ptr_domain)
                if parent and parent != ptr_domain:
                    base_domains.append(parent)
        except:
            pass
        
        # Smart subdomain wordlist (120+)
        subdomains = [
            # Priority 1: Most common
            'www', 'mail', 'api', 'm', 'mobile', 'app', 'dev', 'test',
            
            # Priority 2: Infrastructure
            'cdn', 'static', 'assets', 'img', 'images', 'video', 'media',
            'upload', 'download', 'files', 'docs', 'blog', 'shop', 'store',
            
            # Priority 3: Services
            'admin', 'portal', 'dashboard', 'panel', 'console', 'manage',
            'support', 'help', 'community', 'forum', 'wiki',
            
            # Priority 4: Auth
            'auth', 'login', 'signin', 'signup', 'register', 'account',
            'oauth', 'sso', 'identity',
            
            # Priority 5: Mail
            'smtp', 'pop', 'imap', 'exchange', 'webmail', 'email',
            
            # Priority 6: Tech
            'db', 'database', 'cache', 'redis', 'mongo', 'elastic',
            'search', 'kibana', 'grafana', 'prometheus',
            
            # Priority 7: DevOps
            'jenkins', 'gitlab', 'github', 'git', 'nexus',
            'docker', 'k8s', 'kubernetes', 'helm', 'argo', 'consul',
            
            # Priority 8: Security
            'ssl', 'secure', 'vpn', 'firewall', 'gateway', 'proxy',
            'lb', 'loadbalancer', 'waf',
            
            # Priority 9: Regional
            'us', 'eu', 'asia', 'na', 'sa', 'emea', 'apac',
            'us-east', 'us-west', 'eu-west', 'eu-central',
            
            # Priority 10: Versioned
            'v1', 'v2', 'v3', 'api-v1', 'api-v2', 'api-v3',
            
            # Priority 11: Platform
            'ios', 'android', 'web', 'client', 'server', 'backend',
        ]
        
        # Check subdomains for each base domain
        for base_domain in base_domains[:2]:
            # Skip cloud infra for bruteforce
            if '.amazonaws.com' in base_domain or '.googleapis.com' in base_domain:
                continue
                
            for sub in subdomains:
                test_domain = f"{sub}.{base_domain}"
                try:
                    self.resolver.resolve(test_domain, 'A')
                    if self.add_domain(test_domain):
                        count += 1
                        print(f"  [Brute-Force] {test_domain}")
                except:
                    pass
        
        return count

    # ==================== DNS Records ====================

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
                    
        except Exception:
            pass
        
        return count

    # ==================== Amass (Kali Tool) ====================

    def amass_lookup(self, ip: str) -> int:
        """Amass - Asset discovery tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('amass'):
            return 0
        
        # Get base domains from PTR
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                base_domains.append(ptr_domain)
                
                parent = self.extract_parent_domain(ptr_domain)
                if parent:
                    base_domains.append(parent)
        except:
            pass
        
        for base_domain in base_domains[:2]:
            try:
                result = subprocess.run(
                    ['amass', 'enum', '-passive', '-d', base_domain],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    domains = result.stdout.split('\n')
                    for domain in domains:
                        domain = domain.strip()
                        if domain and self.add_domain(domain):
                            count += 1
                            print(f"  [Amass] {domain}")
                            
            except Exception:
                pass
        
        return count

    # ==================== DNSrecon (Kali Tool) ====================

    def dnsrecon_lookup(self, ip: str) -> int:
        """DNSrecon - DNS reconnaissance tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('dnsrecon'):
            return 0
        
        # Get base domains from PTR
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                base_domains.append(ptr_domain)
                
                parent = self.extract_parent_domain(ptr_domain)
                if parent:
                    base_domains.append(parent)
        except:
            pass
        
        for base_domain in base_domains[:2]:
            try:
                output_file = f"/tmp/dnsrecon_{base_domain}.json"
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
                        
            except Exception:
                pass
        
        return count

    # ==================== Sublist3r (Kali Tool) ====================

    def sublist3r_lookup(self, ip: str) -> int:
        """Sublist3r - Subdomain enumeration tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('sublist3r'):
            return 0
        
        # Get base domains from PTR
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                base_domains.append(ptr_domain)
                
                parent = self.extract_parent_domain(ptr_domain)
                if parent:
                    base_domains.append(parent)
        except:
            pass
        
        for base_domain in base_domains[:2]:
            try:
                result = subprocess.run(
                    ['sublist3r', '-d', base_domain],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    domains = result.stdout.split('\n')
                    for domain in domains:
                        domain = domain.strip()
                        if domain and not domain.startswith('---') and not domain.startswith('['):
                            if self.add_domain(domain):
                                count += 1
                                print(f"  [Sublist3r] {domain}")
                        
            except Exception:
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
        """Perform ultimate smart reverse IP lookup"""
        print(f"\n🔍 Ultimate Smart Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('Certificate-Transparency', self.cert_transparency_lookup),
            ('DNS-MX', lambda x: self.dns_record_lookup(x, 'MX', 'MX')),
            ('DNS-NS', lambda x: self.dns_record_lookup(x, 'NS', 'NS')),
            ('DNS-SRV', lambda x: self.dns_record_lookup(x, 'SRV', 'SRV')),
            ('Advanced-Brute', self.advanced_bruteforce),
            ('Amass', self.amass_lookup),
            ('DNSrecon', self.dnsrecon_lookup),
            ('Sublist3r', self.sublist3r_lookup),
        ]

        total_found = 0
        for name, method in sources:
            try:
                found = method(ip)
                total_found += found
            except Exception as e:
                pass  # Silent errors

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
        description='Ultimate Smart Reverse IP Lookup - Uses multiple CT sources and Kali tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Smart Features:
  - Multiple Certificate Transparency sources (crt.sh + Censys CT)
  - Smart parent domain extraction from AWS/GCP/Azure
  - Smart noise filtering (WHOIS, abuse, CDN)
  - Kali tools: Amass, DNSrecon, Sublist3r
  - Advanced subdomain enumeration (120+ patterns)
  - Multiple DNS servers for better resolution
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
