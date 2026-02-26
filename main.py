#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Simple Fast Version
Uses ONLY Linux CLI tools and Python DNS libraries
"""

import argparse
import socket
import dns.resolver
import dns.reversename
import subprocess
import sys
import re
import os
from typing import Optional, Tuple, Set
import time


class ReverseLookup:
    """Simple fast reverse IP lookup - Linux CLI tools only"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Simple DNS resolver
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 2
            self.resolver.lifetime = 5
        except dns.resolver.NoResolverConfiguration:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.timeout = 2
            self.resolver.lifetime = 5
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']

    def is_valid_domain(self, domain: str) -> bool:
        """Simple domain validation"""
        if not domain or len(domain) < 3:
            return False
        
        clean = domain.lower().strip()
        
        # Skip registry and noise
        skip_patterns = [
            'arin.net', 'rdap.arin.net', 'ripe.net', 'apnic.net',
            'abuse.net', 'dis.abuse', 'knack.black',
        ]
        
        for pattern in skip_patterns:
            if pattern in clean:
                return False
        
        # Must have at least one dot
        if '.' not in clean:
            return False
        
        return True

    def add_domain(self, domain: str) -> bool:
        """Add domain if valid and not duplicate"""
        if self.is_valid_domain(domain):
            clean = domain.lower().strip()
            if clean not in self.domains:
                self.domains.add(clean)
                return True
        return False

    # ==================== Linux: host command ====================

    def host_lookup(self, ip: str) -> int:
        """Linux host command"""
        count = 0
        
        if not self.check_command('host'):
            return 0
        
        try:
            result = subprocess.run(
                ['host', '-t', 'ptr', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Extract domain from output
                pattern = r'domain name pointer\s+([a-zA-Z0-9.-]+)\.'
                matches = re.findall(pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [host] {domain}")
                        
        except Exception as e:
            pass  # Silent errors
        
        return count

    # ==================== Linux: dig command ====================

    def dig_lookup(self, ip: str) -> int:
        """Linux dig command"""
        count = 0
        
        if not self.check_command('dig'):
            return 0
        
        try:
            result = subprocess.run(
                ['dig', '+short', '-x', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Parse output
                domains = result.stdout.strip().split('\n')
                
                for domain in domains:
                    domain = domain.rstrip('.')
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [dig] {domain}")
                        
        except Exception as e:
            pass  # Silent errors
        
        return count

    # ==================== Linux: nslookup command ====================

    def nslookup_lookup(self, ip: str) -> int:
        """Linux nslookup command"""
        count = 0
        
        if not self.check_command('nslookup'):
            return 0
        
        try:
            result = subprocess.run(
                ['nslookup', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Parse output for domain names
                pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})'
                matches = re.findall(pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [nslookup] {domain}")
                        
        except Exception as e:
            pass  # Silent errors
        
        return count

    # ==================== Linux: whois command ====================

    def whois_lookup(self, ip: str) -> int:
        """Linux whois command"""
        count = 0
        
        if not self.check_command('whois'):
            return 0
        
        try:
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract domain names from WHOIS output
                pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})'
                matches = re.findall(pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [whois] {domain}")
                        
        except Exception as e:
            pass  # Silent errors
        
        return count

    # ==================== Python DNS: PTR lookup ====================

    def dns_ptr_lookup(self, ip: str) -> int:
        """Python DNS PTR lookup"""
        count = 0
        
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(reverse_name, 'PTR')
            
            for rdata in answers:
                domain = str(rdata).rstrip('.')
                if self.add_domain(domain):
                    count += 1
                    print(f"  [dns-ptr] {domain}")
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Silent for no PTR
        except Exception as e:
            pass  # Silent errors
        
        return count

    # ==================== Helper Functions ====================

    def check_command(self, command: str) -> bool:
        """Check if a Linux command is available"""
        try:
            subprocess.run(
                ['which', command],
                capture_output=True,
                timeout=3
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
            import json
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
        """Perform simple fast reverse IP lookup"""
        print(f"\n🔍 Simple Fast Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all Linux CLI tools + Python DNS
        sources = [
            ('host', self.host_lookup),
            ('dig', self.dig_lookup),
            ('nslookup', self.nslookup_lookup),
            ('whois', self.whois_lookup),
            ('dns-ptr', self.dns_ptr_lookup),
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
        print(f"   Sources: Linux CLI + Python DNS")

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
        description='Simple Fast Reverse IP Lookup - Linux CLI + Python DNS only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Sources (Linux CLI + Python DNS):
  Linux Tools: host, dig, nslookup, whois
  Python DNS: PTR lookup (dnspython)

NO external APIs, NO Certificate Transparency, NO web scraping.
Uses ONLY local Linux CLI tools and Python DNS libraries.
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
