#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Advanced Smart Version
Find all domains using smart filtering, Kali tools, and advanced Python techniques
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
import hashlib
from typing import Optional, Tuple, Set, List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class ReverseLookup:
    """Smart reverse IP lookup with advanced filtering"""

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
            'iana.org',
            'iana.com',
            'iana-servers.net',
            'iana-servers.org',
            'root-servers.net',
            'iana-servers.com',
        ]
        
        # Abuse and security domains
        abuse_domains = [
            '.abuse', '.spam', '.phish', '.scam',
            'abuse.net', 'dis.abuse', 'dis.incapsula.noc',
            'dis.imperva.rir', 'blacklist', 'spamhaus',
            'spambot', 'malware', 'virus', 'phishing',
        ]
        
        # CDN and cloud infrastructure
        cdn_domains = [
            '.cloudfront.net', '.cloudflare.net', '.cloudflare.com',
            '.fastly.net', '.akamai.net', '.akamaihd.net',
            '.akamaiedge.net', '.akamaitechnologies.com',
            '.cdn77.net', '.cdn.jsdelivr.net',
        ]
        
        # Check all noise patterns
        for noise_domain in registry_domains + abuse_domains + cdn_domains:
            if noise_domain in domain_lower:
                return True
        
        # Check for numeric IP-like domains (reverse DNS noise)
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
            
            # Check for arpa domains
            skip_patterns = ['.in-addr.arpa', '.ip6.arpa', '.compute.amazonaws.com',
                           '.amazonaws.com', '.elasticbeanstalk.com',
                           '.ec2.internal', '.privatelink']
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
                parts = ptr.split('.')
                if len(parts) >= 2:
                    base_domains.append('.'.join(parts[-2:]))
        except:
            pass
        
        if not base_domains:
            return 0
        
        for base_domain in base_domains[:2]:
            url = f"https://crt.sh/?q=%.25252.{base_domain}&output=json"
            
            try:
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = json.loads(response.read().decode('utf-8'))

                for cert in data:
                    domain = cert['name_value'].strip()
                    domain = domain.lstrip('*.')
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [crt.sh] {domain}")

            except Exception as e:
                pass  # Don't print error for CT
        
        return count

    # ==================== Advanced Subdomain Brute Force ====================

    def advanced_bruteforce(self, ip: str) -> int:
        """Advanced subdomain bruteforce with smart wordlist"""
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
        
        # Smart subdomain wordlist (prioritized)
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
            'mail1', 'mail2', 'mx', 'ns1', 'ns2',
            
            # Priority 6: Tech
            'db', 'database', 'cache', 'redis', 'mongo', 'elastic',
            'search', 'kibana', 'grafana', 'prometheus',
            
            # Priority 7: DevOps
            'jenkins', 'gitlab', 'github', 'git', 'svn', 'nexus',
            'docker', 'k8s', 'kubernetes', 'helm', 'argo', 'consul',
            
            # Priority 8: Security
            'ssl', 'secure', 'vpn', 'firewall', 'gateway', 'proxy',
            'lb', 'loadbalancer', 'waf',
            
            # Priority 9: Regional
            'us', 'eu', 'asia', 'na', 'sa', 'emea', 'apac',
            'us-east', 'us-west', 'eu-west', 'eu-central', 'ap-south',
            
            # Priority 10: Versioned
            'v1', 'v2', 'v3', 'v4', 'api-v1', 'api-v2', 'api-v3',
            
            # Priority 11: Platform
            'ios', 'android', 'web', 'client', 'server', 'backend',
            
            # Priority 12: Business
            'hr', 'crm', 'erp', 'billing', 'payment', 'checkout',
            'cart', 'order', 'calendar', 'drive', 'storage',
        ]
        
        # Check subdomains in parallel
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.check_subdomain, f"{sub}.{base_domain}") for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    count += 1
        
        return count

    def check_subdomain(self, domain: str) -> Optional[str]:
        """Check if subdomain exists"""
        try:
            # Try A record
            self.resolver.resolve(domain, 'A')
            if self.add_domain(domain):
                print(f"  [Brute-Force] {domain}")
                return domain
        except:
            pass
        return None

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
            pass  # Silently skip if no records
        
        return count

    # ==================== Amass (Kali Tool) ====================

    def amass_lookup(self, ip: str) -> int:
        """Amass - Asset discovery tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('amass'):
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
            # Run amass enum
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', base_domain],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                # Parse output (domains are one per line)
                domains = result.stdout.split('\n')
                for domain in domains:
                    domain = domain.strip()
                    if domain and self.add_domain(domain):
                        count += 1
                        print(f"  [Amass] {domain}")
                        
        except Exception as e:
            pass
        
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
            output_file = f"/tmp/dnsrecon_{base_domain}.json"
            result = subprocess.run(
                ['dnsrecon', '-d', base_domain, '-j', output_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse JSON output
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                    
                    # Extract from various sections
                    if 'ptr' in data:
                        for record in data['ptr']:
                            if 'name' in record:
                                domain = record['name'].rstrip('.')
                                if self.add_domain(domain):
                                    count += 1
                                    print(f"  [DNSrecon] {domain}")
                    
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
                    
                    # Clean up
                    os.remove(output_file)
                except:
                    pass
                        
        except Exception as e:
            pass
        
        return count

    # ==================== Sublist3r (Kali Tool) ====================

    def sublist3r_lookup(self, ip: str) -> int:
        """Sublist3r - Subdomain enumeration tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('sublist3r'):
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
            result = subprocess.run(
                ['sublist3r', '-d', base_domain],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Parse output (domains are one per line)
                domains = result.stdout.split('\n')
                for domain in domains:
                    domain = domain.strip()
                    # Skip lines that aren't domains
                    if domain and not domain.startswith('---') and not domain.startswith('['):
                        if self.add_domain(domain):
                            count += 1
                            print(f"  [Sublist3r] {domain}")
                        
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
        """Perform smart reverse IP lookup"""
        print(f"\n🔍 Smart Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('crt.sh', self.crtsh_lookup),
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
                pass  # Silently skip errors

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
        description='Smart Reverse IP Lookup - Uses Kali tools and advanced Python',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Kali Linux Tools (if available):
  amass      - Asset discovery (install: apt install amass)
  dnsrecon   - DNS recon (install: apt install dnsrecon)
  sublist3r   - Subdomain enum (install: apt install sublist3r)

Smart Filtering:
  - Removes WHOIS noise (arin.net, rdap.arin.net, etc.)
  - Removes abuse domains (abuse.net, dis.incapsula.noc, etc.)
  - Removes CDN infrastructure (cloudflare.net, akamai.net, etc.)
  - Prioritizes relevant domains
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
