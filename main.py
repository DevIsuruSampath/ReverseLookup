#!/usr/bin/env python3
"""
Reverse IP Lookup Tool - Pure DNS Version
Find all domains on an IP using only DNS queries and Python libraries
No external data sources or APIs required
"""

import argparse
import socket
import dns.resolver
import dns.reversename
import subprocess
import sys
import re
from typing import Optional, Tuple
import time


class ReverseLookup:
    """Reverse IP lookup using only DNS queries"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains = set()
        self.output_file = output_file
        self.output_format = output_format
        
        # Initialize DNS resolver with Termux compatibility
        # Try to create resolver, catch Termux resolv.conf error
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
        except dns.resolver.NoResolverConfiguration:
            # Termux/Android compatibility - manually create resolver
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
            # Use public DNS servers
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']

    def add_domain(self, domain: str) -> bool:
        """Add domain if not duplicate"""
        if domain and '.' in domain and len(domain) > 3:
            clean = domain.lower().strip()
            # Filter out arpa domains and invalid patterns
            if 'in-addr.arpa' not in clean and 'ip6.arpa' not in clean:
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

    # ==================== DNS MX Records ====================

    def dns_mx_lookup(self, ip: str) -> int:
        """DNS MX record lookup for mail servers"""
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
            mx_answers = self.resolver.resolve(base_domain, 'MX')
            
            for rdata in mx_answers:
                mail_server = rdata.exchange.to_text().rstrip('.')
                if self.add_domain(mail_server):
                    count += 1
                    print(f"  [DNS-MX] {mail_server}")
                    
        except Exception as e:
            print(f"  [DNS-MX] Error: {e}")
        
        return count

    # ==================== DNS NS Records ====================

    def dns_ns_lookup(self, ip: str) -> int:
        """DNS NS record lookup for name servers"""
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
            ns_answers = self.resolver.resolve(base_domain, 'NS')
            
            for rdata in ns_answers:
                nameserver = rdata.target.to_text().rstrip('.')
                if self.add_domain(nameserver):
                    count += 1
                    print(f"  [DNS-NS] {nameserver}")
                    
        except Exception as e:
            print(f"  [DNS-NS] Error: {e}")
        
        return count

    # ==================== DNS TXT Records ====================

    def dns_txt_lookup(self, ip: str) -> int:
        """DNS TXT record lookup (may contain domain info)"""
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
            txt_answers = self.resolver.resolve(base_domain, 'TXT')
            
            # Extract domains from TXT records
            domain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
            
            for rdata in txt_answers:
                txt_record = str(rdata)
                matches = re.findall(domain_pattern, txt_record)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [DNS-TXT] {domain}")
                        
        except Exception as e:
            print(f"  [DNS-TXT] Error: {e}")
        
        return count

    # ==================== System host command ====================

    def host_command(self, ip: str) -> int:
        """System host command for PTR lookup"""
        count = 0
        try:
            result = subprocess.run(
                ['host', '-t', 'ptr', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                pattern = r'domain name pointer\s+([a-zA-Z0-9.-]+)\.'
                matches = re.findall(pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Host] {domain}")
                        
        except Exception as e:
            print(f"  [Host] Error: {e}")
        
        return count

    # ==================== System nslookup command ====================

    def nslookup_command(self, ip: str) -> int:
        """System nslookup command for PTR lookup"""
        count = 0
        try:
            result = subprocess.run(
                ['nslookup', '-type=PTR', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Nslookup] {domain}")
                        
        except Exception as e:
            print(f"  [Nslookup] Error: {e}")
        
        return count

    # ==================== System dig command ====================

    def dig_command(self, ip: str) -> int:
        """System dig command for PTR lookup"""
        count = 0
        try:
            result = subprocess.run(
                ['dig', '+short', '-x', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(pattern, result.stdout)
                
                for domain in matches:
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Dig] {domain}")
                        
        except Exception as e:
            print(f"  [Dig] Error: {e}")
        
        return count

    # ==================== DNS Subdomain Brute Force ====================

    def dns_bruteforce(self, ip: str) -> int:
        """DNS bruteforce - try common subdomains with PTR"""
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
        
        # Common subdomains list
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'staging', 'dev', 'test',
            'blog', 'shop', 'store', 'secure', 'vpn', 'cdn', 'static', 'assets',
            'img', 'images', 'video', 'media', 'upload', 'download', 'files',
            'docs', 'wiki', 'help', 'support', 'forum', 'community', 'news',
            'events', 'calendar', 'crm', 'erp', 'portal', 'dashboard', 'panel',
            'app', 'apps', 'mobile', 'm', 'wap', 'web', 'ns1', 'ns2', 'ns3',
            'pop', 'imap', 'smtp', 'mx', 'exchange', 'email', 'webmail',
            'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
            'cache', 'memcache', 'varnish', 'lb', 'loadbalancer', 'proxy',
            'firewall', 'gateway', 'router', 'switch', 'server', 'host',
            'node1', 'node2', 'node3', 'master', 'slave', 'worker'
        ]
        
        # Try each subdomain
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

    # ==================== DNS SRV Records ====================

    def dns_srv_lookup(self, ip: str) -> int:
        """DNS SRV record lookup for services"""
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
        
        # Common SRV services
        srv_services = [
            '_sip._tcp', '_sips._tcp', '_xmpp-server._tcp', '_xmpp-client._tcp',
            '_ldap._tcp', '_ldaps._tcp', '_kerberos._tcp', '_kerberos._udp',
            '_kpasswd._tcp', '_kpasswd._udp', '_imap._tcp', '_imaps._tcp',
            '_pop3._tcp', '_pop3s._tcp', '_smtp._tcp', '_submission._tcp',
            '_ftp._tcp', '_ftps._tcp', '_http._tcp', '_https._tcp',
            '_caldav._tcp', '_carddav._tcp', '_caldavs._tcp', '_carddavs._tcp',
            '_git._tcp', '_ssh._tcp', '_telnet._tcp', '_ws._tcp', '_wss._tcp'
        ]
        
        for service in srv_services:
            srv_domain = f"{service}.{base_domain}"
            try:
                srv_answers = self.resolver.resolve(srv_domain, 'SRV')
                
                for rdata in srv_answers:
                    target = rdata.target.to_text().rstrip('.')
                    if self.add_domain(target):
                        count += 1
                        print(f"  [DNS-SRV] {target}")
                        
            except:
                pass
        
        return count

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
        """Perform reverse IP lookup using all DNS sources"""
        print(f"\n🔍 Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        start_time = time.time()

        # Run all DNS sources
        sources = [
            ('DNS-PTR', self.dns_ptr_lookup),
            ('Host', self.host_command),
            ('Nslookup', self.nslookup_command),
            ('Dig', self.dig_command),
            ('DNS-MX', self.dns_mx_lookup),
            ('DNS-NS', self.dns_ns_lookup),
            ('DNS-TXT', self.dns_txt_lookup),
            ('DNS-SRV', self.dns_srv_lookup),
            ('Brute-Force', self.dns_bruteforce),
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
        description='Pure DNS Reverse IP Lookup - Find domains using only DNS queries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --output results.txt
  %(prog)s google.com --format json --output domains.json

Note: This version uses ONLY DNS queries and system tools.
No external data sources or APIs are used.
Fully compatible with Termux on Android.
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
