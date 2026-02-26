#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Ultimate Fast Version
Fast smart lookup with proper filtering and real domain discovery
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
from typing import Optional, Tuple, Set
import time


class ReverseLookup:
    """Ultimate fast smart reverse IP lookup"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Initialize DNS resolver with fast settings
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 3
            self.resolver.lifetime = 6
        except dns.resolver.NoResolverConfiguration:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.timeout = 3
            self.resolver.lifetime = 6
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']

    def is_valid_domain(self, domain: str) -> bool:
        """Check if domain is a valid domain (not noise)"""
        if not domain or '.' not in domain or len(domain) < 3:
            return False
        
        clean = domain.lower().strip()
        
        # Skip ASN, netblock, IP-like, and other noise
        skip_patterns = [
            '(', ')', '[', ']', '{', '}',
            'asn', 'netblock', 'netmask',
            'managed_by', 'rirorganization',
            'announces', '/24', '/16', '/8',
            '14618', '23.20.0.0',
            'amazon-aes', 'amazon.com, inc.',
        ]
        
        for pattern in skip_patterns:
            if pattern in clean:
                return False
        
        # Check for pure numeric or IP-like domains
        if re.match(r'^\d+[-.]\d+', clean):
            return False
        
        # Check for dis/knack abuse patterns
        if clean.startswith('ww.dis.') or clean.startswith('knack.'):
            return False
        
        return True

    def is_cloud_or_registry_domain(self, domain: str) -> bool:
        """Check if domain is cloud infra, registry, or CDN"""
        domain_lower = domain.lower()
        
        # AWS patterns (comprehensive)
        aws_patterns = [
            '.amazonaws.com', '.amazonaws.com.cn',
            '.compute.amazonaws.com', '.compute-1.amazonaws.com',
            '.ec2.internal', '.ec2.amazonaws.com',
            'waf.amazonaws.com', 'support.amazonaws.com',
            'www.amazonaws.com', 'elasticbeanstalk.com',
            '.cloudfront.net', '.cloudfront.lamba.amazonaws.com',
            '.s3.amazonaws.com', '.s3-website.amazonaws.com',
            '.route53.amazonaws.com',
        ]
        
        # GCP patterns
        gcp_patterns = [
            '.googleapis.com', '.googleusercontent.com',
            '.cloudfunctions.net', '.appspot.com',
            '.gcp.cloud.google.com',
        ]
        
        # Azure patterns
        azure_patterns = [
            '.cloudapp.azure.com', '.azurewebsites.net',
            '.windowsazure.com', '.azure.net',
            '.azure-mobile.net',
        ]
        
        # CDN patterns
        cdn_patterns = [
            '.cloudflare.net', '.cloudflare.com',
            '.fastly.net', '.fastly.com',
            '.akamai.net', '.akamaihd.net',
            '.akamaiedge.net', '.akamaitechnologies.com',
            '.cdn77.net', '.cdn.jsdelivr.net',
            '.bootstrapcdn.com', '.cdnjs.cloudflare.com',
        ]
        
        # Registry/RIR domains
        registry_domains = [
            'arin.net', 'rdap.arin.net', 'www.arin.net',
            'ripe.net', 'rdap.ripe.net', 'www.ripe.net',
            'apnic.net', 'rdap.apnic.net',
            'lacnic.net', 'rdap.lacnic.net',
            'afrinic.net', 'rdap.afrinic.net',
            'iana.org', 'iana-servers.net',
            'root-servers.net', 'iana-servers.com',
        ]
        
        # Abuse/security domains
        abuse_domains = [
            '.abuse', '.spam', '.phish', '.scam',
            'abuse.net', 'dis.abuse', 'dis.incapsula.noc',
            'dis.imperva.rir', 'blacklist', 'spamhaus',
            'knack.black',
        ]
        
        # Check all patterns
        for pattern in aws_patterns + gcp_patterns + azure_patterns + cdn_patterns + registry_domains + abuse_domains:
            if pattern in domain_lower:
                return True
        
        return False

    def add_domain(self, domain: str) -> bool:
        """Add domain if valid and not noise"""
        if not self.is_valid_domain(domain):
            return False
        
        clean = domain.lower().strip()
        
        # Check for cloud/registry domains
        if self.is_cloud_or_registry_domain(clean):
            return False
        
        # Add if not duplicate
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
            pass  # Silent
        except Exception:
            pass  # Silent errors
        
        return count

    # ==================== Certificate Transparency (crt.sh) ====================

    def crtsh_lookup(self, ip: str) -> int:
        """Certificate Transparency lookup via crt.sh"""
        count = 0
        
        # Get base domain from PTR
        base_domain = None
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            if ptr_answers:
                ptr_domain = str(ptr_answers[0]).rstrip('.')
                
                # Extract 2nd-level domain for CT search
                parts = ptr_domain.split('.')
                if len(parts) >= 2:
                    base_domain = '.'.join(parts[-2:])
        except:
            pass
        
        if not base_domain:
            return 0
        
        # Skip cloud infra for CT
        if self.is_cloud_or_registry_domain(base_domain):
            return 0
        
        url = f"https://crt.sh/?q=%.25252.{base_domain}&output=json"
        
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                data = json.loads(response.read().decode('utf-8'))

            # Limit to first 30 certificates for speed
            for cert in data[:30]:
                domain = cert['name_value'].strip()
                domain = domain.lstrip('*.')
                if self.add_domain(domain):
                    count += 1
                    print(f"  [crt.sh] {domain}")

        except Exception:
            pass  # Silent
        
        return count

    # ==================== Fast Subdomain Brute Force ====================

    def fast_bruteforce(self, ip: str) -> int:
        """Fast subdomain bruteforce with 40 most common subdomains"""
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
        
        # Skip cloud infra for bruteforce
        if self.is_cloud_or_registry_domain(base_domain):
            return 0
        
        # 40 most common subdomains
        subdomains = [
            'www', 'mail', 'api', 'm', 'mobile', 'app', 'dev', 'test',
            'cdn', 'static', 'assets', 'img', 'images', 'video', 'media',
            'upload', 'download', 'files', 'docs', 'blog', 'shop', 'store',
            'admin', 'portal', 'dashboard', 'panel', 'console', 'manage',
            'support', 'help', 'community', 'forum', 'wiki',
            'auth', 'login', 'signin', 'signup', 'register', 'account',
            'smtp', 'pop', 'imap', 'exchange', 'email', 'webmail',
        ]
        
        # Check each subdomain
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
            pass  # Silent skip
        
        return count

    # ==================== Amass (Clean Parsing) ====================

    def amass_lookup(self, ip: str) -> int:
        """Amass with clean parsing (no ASN/netblock noise)"""
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
        
        if not base_domain:
            return 0
        
        # Skip cloud infra for Amass
        if self.is_cloud_or_registry_domain(base_domain):
            return 0
        
        try:
            # Amass passive mode
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', base_domain],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse output carefully
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    
                    # Skip non-domain lines
                    if not line:
                        continue
                    if line.startswith('[') or line.startswith('|'):
                        continue
                    if 'asn' in line.lower() or 'netblock' in line.lower():
                        continue
                    if 'managed_by' in line or 'rirorganization' in line:
                        continue
                    if line.isdigit():
                        continue
                    if '/' in line and not '.' in line:  # IP range like 23.20.0.0/14
                        continue
                    if line.count('.') != 2:  # Need at least 2 dots for domain
                        continue
                    
                    # Should be a domain now
                    if self.add_domain(line):
                        count += 1
                        print(f"  [Amass] {line}")
                        
        except subprocess.TimeoutExpired:
            pass  # Silent timeout
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
        """Perform ultimate fast smart reverse IP lookup"""
        print(f"\n🔍 Ultimate Fast Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('crt.sh', self.crtsh_lookup),
            ('DNS-MX', lambda x: self.dns_record_lookup(x, 'MX', 'MX')),
            ('DNS-NS', lambda x: self.dns_record_lookup(x, 'NS', 'NS')),
            ('DNS-SRV', lambda x: self.dns_record_lookup(x, 'SRV', 'SRV')),
            ('Brute-Force', self.fast_bruteforce),
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
        description='Ultimate Fast Reverse IP Lookup - Smart filtering, fast CT',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Smart Features:
  - Proper cloud/registry/CDN domain filtering
  - Clean Amass output (no ASN/netblock noise)
  - Fast Certificate Transparency (30 certs only)
  - Fast subdomain bruteforce (40 most common)
  - Silent error handling for clean output

Kali Tools (if available):
  - Amass passive mode (30s timeout)
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
