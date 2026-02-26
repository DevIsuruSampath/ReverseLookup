#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Enhanced Linux/Kali Version
Find all domains on an IP using DNS, Linux tools, and Python libraries
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
    """Reverse IP lookup using DNS, Linux tools, and Python libraries"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Initialize DNS resolver with Termux compatibility
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
            # Filter out arpa domains, aws, and invalid patterns
            skip_patterns = ['.in-addr.arpa', '.ip6.arpa', '.compute.amazonaws.com',
                           '.amazonaws.com', '.cloudfront.net', '.elasticbeanstalk.com']
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

    # ==================== WHOIS Tool ====================

    def whois_lookup(self, ip: str) -> int:
        """WHOIS lookup for domain information"""
        count = 0
        
        # Check if whois is available
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
                # Extract domain names from WHOIS output
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
            print(f"  [DNSrecon] Tool not found (install: apt install dnsrecon)")
            return 0
        
        try:
            output_file = f"/tmp/dnsrecon_{ip.replace('.', '_')}.json"
            result = subprocess.run(
                ['dnsrecon', '-t', ip, '-j', output_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse JSON output if it exists
            if os.path.exists(output_file):
                try:
                    import json
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                    
                    # Extract domains from different sections
                    if 'ptr' in data:
                        for record in data['ptr']:
                            if 'name' in record:
                                domain = record['name'].rstrip('.')
                                if self.add_domain(domain):
                                    count += 1
                                    print(f"  [DNSrecon] {domain}")
                    
                    if 'ns' in data:
                        for record in data['ns']:
                            if 'target' in record:
                                domain = record['target'].rstrip('.')
                                if self.add_domain(domain):
                                    count += 1
                                    print(f"  [DNSrecon] {domain}")
                    
                    # Clean up
                    os.remove(output_file)
                except:
                    pass
                        
        except Exception as e:
            print(f"  [DNSrecon] Error: {e}")
        
        return count

    # ==================== DNSenum (Kali Tool) ====================

    def dnsenum_lookup(self, ip: str) -> int:
        """DNSenum - DNS enumeration tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('dnsenum'):
            print(f"  [DNSenum] Tool not found (install: apt install dnsenum)")
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
                ['dnsenum', base_domain],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Extract domains from output
                domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(domain_pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [DNSenum] {domain}")
                        
        except Exception as e:
            print(f"  [DNSenum] Error: {e}")
        
        return count

    # ==================== Fierce (Kali Tool) ====================

    def fierce_lookup(self, ip: str) -> int:
        """Fierce - DNS scanner (Kali Linux)"""
        count = 0
        
        if not self.check_command('fierce'):
            print(f"  [Fierce] Tool not found (install: apt install fierce)")
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
                ['fierce', '--domain', base_domain],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Extract domains from output
                domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(domain_pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Fierce] {domain}")
                        
        except Exception as e:
            print(f"  [Fierce] Error: {e}")
        
        return count

    # ==================== amass (Kali Tool) ====================

    def amass_lookup(self, ip: str) -> int:
        """Amass - Asset discovery tool (Kali Linux)"""
        count = 0
        
        if not self.check_command('amass'):
            print(f"  [Amass] Tool not found (install: apt install amass)")
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
                ['amass', 'enum', '-passive', '-d', base_domain],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                # Extract domains
                domains = result.stdout.split('\n')
                for domain in domains:
                    domain = domain.strip()
                    if domain and self.add_domain(domain):
                        count += 1
                        print(f"  [Amass] {domain}")
                        
        except Exception as e:
            print(f"  [Amass] Error: {e}")
        
        return count

    # ==================== dig axfr ====================

    def dig_axfr(self, ip: str) -> int:
        """DIG AXFR - Zone transfer attempt"""
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
        
        # Get nameservers
        try:
            ns_answers = self.resolver.resolve(base_domain, 'NS')
            nameservers = [str(ns) for ns in ns_answers]
            
            for ns in nameservers:
                try:
                    result = subprocess.run(
                        ['dig', 'axfr', base_domain, '@' + ns],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0 and 'XFR' in result.stdout:
                        # Parse AXFR output
                        domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                        matches = re.findall(domain_pattern, result.stdout)
                        
                        for domain in matches:
                            if self.add_domain(domain):
                                count += 1
                                print(f"  [DIG-AXFR] {domain}")
                                
                except:
                    pass
                    
        except Exception as e:
            print(f"  [DIG-AXFR] Error: {e}")
        
        return count

    # ==================== Nmap ====================

    def nmap_lookup(self, ip: str) -> int:
        """Nmap - Network mapper for service discovery"""
        count = 0
        
        if not self.check_command('nmap'):
            print(f"  [Nmap] Tool not found (install: apt install nmap)")
            return 0
        
        try:
            # Quick scan for HTTP/HTTPS services
            result = subprocess.run(
                ['nmap', '-p', '80,443,8080,8443', '--script', 'http-title', ip],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Extract domains from Nmap output
                domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(domain_pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Nmap] {domain}")
                        
        except Exception as e:
            print(f"  [Nmap] Error: {e}")
        
        return count

    # ==================== DNSMX, NS, TXT, SRV ====================

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
        """Perform reverse IP lookup using all available tools"""
        print(f"\n🔍 Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('WHOIS', self.whois_lookup),
            ('DNS-MX', lambda x: self.dns_record_lookup(x, 'MX', 'MX')),
            ('DNS-NS', lambda x: self.dns_record_lookup(x, 'NS', 'NS')),
            ('DNS-TXT', lambda x: self.dns_record_lookup(x, 'TXT', 'TXT')),
            ('DNS-SRV', lambda x: self.dns_record_lookup(x, 'SRV', 'SRV')),
            ('DNSrecon', self.dnsrecon_lookup),
            ('DNSenum', self.dnsenum_lookup),
            ('Fierce', self.fierce_lookup),
            ('Amass', self.amass_lookup),
            ('DIG-AXFR', self.dig_axfr),
            ('Nmap', self.nmap_lookup),
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
        description='Enhanced Reverse IP Lookup - Uses DNS, Linux tools, and Python libraries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Kali Linux Tools Used (if available):
  dnsrecon - DNS reconnaissance tool
  dnsenum  - DNS enumeration tool
  fierce    - DNS scanner
  amass     - Asset discovery tool
  nmap      - Network mapper
  whois     - WHOIS client

Note: This tool works on standard Linux too.
Kali tools are optional and used if available.
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
        # It's an IP address
        target_ip = args.target
        print(f"📍 Target: {args.target} (IP address)")
    elif validate_domain(args.target):
        # It's a domain - resolve to IP
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
