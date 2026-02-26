#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Fast Smart Version
Find domains using smart filtering, fast CT sources, and optional Kali tools
"""

import argparse
import socket
import dns.resolver
import dns.reversename
import subprocess
import sys
import re
import os
import urllib.request
import json
from typing import Optional, Tuple, Set, List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class ReverseLookup:
    """Fast smart reverse IP lookup"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Initialize DNS resolver
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 3
            self.resolver.lifetime = 8
        except dns.resolver.NoResolverConfiguration:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.timeout = 3
            self.resolver.lifetime = 8
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']

    def is_cloud_infra_domain(self, domain: str) -> bool:
        """Check if domain is cloud infrastructure"""
        domain_lower = domain.lower()
        
        # AWS patterns
        aws_patterns = [
            '.amazonaws.com', '.amazonaws.com.cn', '.compute.amazonaws.com',
            '.compute-1.amazonaws.com', '.ec2.internal',
            'waf.amazonaws.com', 'support.amazonaws.com',
            'www.amazonaws.com', 'elasticbeanstalk.com',
        ]
        
        # GCP patterns
        gcp_patterns = [
            '.googleapis.com', '.googleusercontent.com',
            '.cloudfunctions.net', '.appspot.com',
        ]
        
        # Azure patterns
        azure_patterns = [
            '.cloudapp.azure.com', '.azurewebsites.net',
            '.windowsazure.com', '.azure.net',
        ]
        
        # Check all cloud patterns
        for pattern in aws_patterns + gcp_patterns + azure_patterns:
            if pattern in domain_lower:
                return True
        
        return False

    def add_domain(self, domain: str) -> bool:
        """Add domain if not duplicate and not noise"""
        if domain and '.' in domain and len(domain) > 3:
            clean = domain.lower().strip()
            
            # Check for cloud infrastructure
            if self.is_cloud_infra_domain(clean):
                return False
            
            # Registry and RIR domains
            registry_domains = [
                'arin.net', 'rdap.arin.net', 'www.arin.net',
                'ripe.net', 'rdap.ripe.net', 'www.ripe.net',
                'apnic.net', 'rdap.apnic.net',
                'lacnic.net', 'rdap.lacnic.net',
                'afrinic.net', 'rdap.afrinic.net',
                'iana.org', 'iana-servers.net',
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
                if noise_domain in clean:
                    return False
            
            # Check for numeric IP-like domains
            if re.match(r'^\d+[-.]\d+', clean):
                return False
            
            # Check for dis/disabuse patterns
            if clean.startswith('ww.dis.') or clean.startswith('knack.'):
                return False
            
            if clean not in self.domains:
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
            pass  # Silent for no PTR
        except Exception as e:
            pass  # Silent errors
        
        return count

    # ==================== Certificate Transparency (Fast) ====================

    def cert_transparency_lookup(self, ip: str) -> int:
        """Fast Certificate Transparency lookup"""
        count = 0
        
        # Get base domains from PTR
        base_domains = []
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                base_domains.append(ptr_domain)
        except:
            pass
        
        # Search each base domain in crt.sh only (fastest)
        for base_domain in base_domains[:1]:
            url = f"https://crt.sh/?q=%.25252.{base_domain}&output=json"
            
            try:
                with urllib.request.urlopen(url, timeout=20) as response:
                    data = json.loads(response.read().decode('utf-8'))

                # Limit to first 50 certificates for speed
                for cert in data[:50]:
                    domain = cert['name_value'].strip()
                    domain = domain.lstrip('*.')
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [crt.sh] {domain}")

            except Exception:
                pass  # Silent errors
        
        return count

    # ==================== Fast Subdomain Brute Force ====================

    def fast_bruteforce(self, ip: str) -> int:
        """Fast subdomain bruteforce with 60 common subdomains"""
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
        
        if not base_domain or self.is_cloud_infra_domain(base_domain):
            return 0
        
        # Fast subdomain wordlist (60 most common)
        subdomains = [
            'www', 'mail', 'api', 'm', 'mobile', 'app', 'dev', 'test',
            'cdn', 'static', 'assets', 'img', 'images', 'video', 'media',
            'upload', 'download', 'files', 'docs', 'blog', 'shop', 'store',
            'admin', 'portal', 'dashboard', 'panel', 'console', 'manage',
            'support', 'help', 'forum', 'community', 'wiki',
            'auth', 'login', 'signin', 'signup', 'register', 'account',
            'smtp', 'pop', 'imap', 'exchange', 'email', 'webmail',
            'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'db', 'cache', 'lb',
            'us', 'eu', 'asia', 'v1', 'v2', 'v3', 'ios', 'android',
        ]
        
        # Check subdomains in parallel
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.check_subdomain, f"{sub}.{base_domain}") for sub in subdomains}
            
            for future in as_completed(futures, timeout=15):
                try:
                    result = future.result()
                    if result:
                        count += 1
                except:
                    pass
        
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
        
        if not base_domain or self.is_cloud_infra_domain(base_domain):
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
            pass  # Silent skip
        
        return count

    # ==================== Amass (Fast Mode) ====================

    def amass_lookup(self, ip: str) -> int:
        """Amass - Fast passive mode only"""
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
        
        if not base_domain or self.is_cloud_infra_domain(base_domain):
            return 0
        
        try:
            # Amass passive mode only (faster)
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', base_domain],
                capture_output=True,
                text=True,
                timeout=45  # Reduced timeout
            )
            
            if result.returncode == 0:
                # Parse output (domains are one per line)
                # Filter out progress and noise
                lines = result.stdout.split('\n')
                for line in lines:
                    domain = line.strip()
                    # Skip Amass output lines that aren't domains
                    if not domain:
                        continue
                    if domain.startswith('[') or domain.startswith('|'):
                        continue
                    if '(' in domain or ')' in domain:
                        continue
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Amass] {domain}")
                        
        except subprocess.TimeoutExpired:
            print(f"  [Amass] Timeout (45s)")
        except Exception:
            pass  # Silent errors
        
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
        """Perform fast smart reverse IP lookup"""
        print(f"\n🔍 Fast Smart Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('Certificate-Transparency', self.cert_transparency_lookup),
            ('DNS-MX', lambda x: self.dns_record_lookup(x, 'MX', 'MX')),
            ('DNS-NS', lambda x: self.dns_record_lookup(x, 'NS', 'NS')),
            ('Fast-Brute', self.fast_bruteforce),
            ('Amass', self.amass_lookup),
        ]

        total_found = 0
        for name, method in sources:
            try:
                found = method(ip)
                total_found += found
            except Exception:
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
        description='Fast Smart Reverse IP Lookup - Fast CT, smart filtering, optional Kali tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Smart Features:
  - Cloud infrastructure filtering (AWS/GCP/Azure)
  - Fast Certificate Transparency (crt.sh only)
  - Fast subdomain bruteforce (60 common)
  - Smart noise filtering
  - Amass passive mode (45s timeout)
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
