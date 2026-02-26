#!/usr/bin/env python3
"""
Reverse IP Lookup Tool
Find all domains hosted on a specific IP address
Enhanced with multiple sources and Python libraries
"""

import argparse
import asyncio
import aiohttp
import json
import re
import socket
import sys
import dns.resolver
import subprocess
from typing import List, Set, Optional, Tuple, Dict
from urllib.parse import quote, urlencode
import time
import os


class ReverseLookup:
    """Reverse IP lookup using multiple sources"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt',
                 api_keys: Optional[Dict[str, str]] = None):
        self.domains: Set[str] = set()
        self.output_file = output_file
        self.output_format = output_format
        self.api_keys = api_keys or {}
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def add_domain(self, domain: str) -> bool:
        """Add domain if not duplicate"""
        if domain and '.' in domain and len(domain) > 3:
            clean = domain.lower().strip()
            # Filter out common false positives
            skip_patterns = ['.cloudflare.com', '.cloudflare.net', '.akamai.net', '.akamaized.net',
                           '.fastly.net', '.cloudfront.net', '.amazonaws.com', '.googleusercontent.com']
            if not any(pattern in clean for pattern in skip_patterns):
                if clean not in self.domains:
                    self.domains.add(clean)
                    return True
        return False

    # ==================== DNS-Based Sources ====================

    async def source_dns_ptr(self, ip: str, limit: Optional[int] = None) -> int:
        """DNS PTR record lookup using dnspython"""
        count = 0
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            
            # Get PTR record
            answers = resolver.resolve(ip, 'PTR')
            for rdata in answers:
                if limit and count >= limit:
                    break
                domain = str(rdata).rstrip('.')
                if self.add_domain(domain):
                    count += 1
                    print(f"  [DNS-PTR] {domain}")
                    
        except Exception as e:
            print(f"  [DNS-PTR] Error: {e}")
        return count

    async def source_dns_bruteforce(self, ip: str, limit: Optional[int] = None) -> int:
        """DNS bruteforce using common subdomains"""
        count = 0
        subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'staging', 'dev', 'test',
                      'blog', 'shop', 'secure', 'vpn', 'cdn', 'static', 'assets', 'img']
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            
            # Get the base domain from PTR if available
            base_domain = None
            try:
                ptr_answers = resolver.resolve(ip, 'PTR')
                if ptr_answers:
                    base_domain = str(ptr_answers[0]).rstrip('.')
            except:
                pass
            
            # Try common subdomains with different domains found from PTR
            if base_domain:
                for sub in subdomains:
                    if limit and count >= limit:
                        break
                    test_domain = f"{sub}.{base_domain}"
                    try:
                        resolver.resolve(test_domain, 'A')
                        if self.add_domain(test_domain):
                            count += 1
                            print(f"  [DNS-Brute] {test_domain}")
                    except:
                        pass
                        
        except Exception as e:
            print(f"  [DNS-Brute] Error: {e}")
        return count

    async def source_host(self, ip: str, limit: Optional[int] = None) -> int:
        """System host command for DNS lookup"""
        count = 0
        try:
            result = subprocess.run(['host', '-t', 'ptr', ip], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse output for domain names
                pattern = r'domain name pointer\s+([a-zA-Z0-9.-]+)\.'
                matches = re.findall(pattern, result.stdout)
                for domain in matches:
                    if limit and count >= limit:
                        break
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Host] {domain}")
        except Exception as e:
            print(f"  [Host] Error: {e}")
        return count

    # ==================== Web Scraping Sources ====================

    async def source_viewdns(self, ip: str, limit: Optional[int] = None) -> int:
        """ViewDNS.info API (free with rate limiting)"""
        url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
        count = 0

        try:
            await asyncio.sleep(1)  # Rate limiting
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Parse HTML response - more robust pattern
            pattern = r'<td>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}\.[a-zA-Z]{2,})</td>'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [ViewDNS] {domain}")

        except Exception as e:
            print(f"  [ViewDNS] Error: {e}")

        return count

    async def source_bing(self, ip: str, limit: Optional[int] = None) -> int:
        """Bing search for IP references"""
        count = 0
        max_pages = 5 if not limit else min(5, (limit // 10) + 1)

        for page in range(max_pages):
            if limit and count >= limit:
                break

            offset = page * 10
            query = f"ip:{ip}"
            url = f"https://www.bing.com/search?q={quote(query)}&first={offset}"

            try:
                await asyncio.sleep(2)  # Rate limiting
                async with self.session.get(url) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text()

                # Extract domains from search results - improved pattern
                pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
                matches = re.findall(pattern, text)

                for domain in matches:
                    if limit and count >= limit:
                        break
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [Bing] {domain}")

            except Exception as e:
                print(f"  [Bing] Page {page} Error: {e}")

        return count

    async def source_duckduckgo(self, ip: str, limit: Optional[int] = None) -> int:
        """DuckDuckGo search for IP references"""
        count = 0
        query = f"ip:{ip}"
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"

        try:
            await asyncio.sleep(1)
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Extract domains from search results
            pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [DuckDuckGo] {domain}")

        except Exception as e:
            print(f"  [DuckDuckGo] Error: {e}")

        return count

    async def source_netcraft(self, ip: str, limit: Optional[int] = None) -> int:
        """Netcraft site report"""
        count = 0
        url = f"https://searchdns.netcraft.com/?restriction=site+contains&host={quote(ip)}"

        try:
            await asyncio.sleep(2)
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Parse domains - improved pattern
            pattern = r'<a[^>]*href="https?://([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})"'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [Netcraft] {domain}")

        except Exception as e:
            print(f"  [Netcraft] Error: {e}")

        return count

    async def source_yougetsignal(self, ip: str, limit: Optional[int] = None) -> int:
        """YouGetSignal reverse IP lookup"""
        count = 0
        url = "https://www.yougetsignal.com/tools/web-sites-on-web-server/"
        
        try:
            await asyncio.sleep(2)
            data = {'remoteAddress': ip}
            async with self.session.post(url, data=data) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Parse JSON response or text
            try:
                result = json.loads(text)
                if 'domainArray' in result:
                    for domain_info in result['domainArray']:
                        domain = domain_info[0]
                        if limit and count >= limit:
                            break
                        if self.add_domain(domain):
                            count += 1
                            print(f"  [YouGetSignal] {domain}")
            except:
                # Fallback to text parsing
                pattern = r'[a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,}'
                matches = re.findall(pattern, text)
                for domain in matches:
                    if limit and count >= limit:
                        break
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [YouGetSignal] {domain}")

        except Exception as e:
            print(f"  [YouGetSignal] Error: {e}")

        return count

    async def source_iphostinfo(self, ip: str, limit: Optional[int] = None) -> int:
        """IPHostInfo reverse IP lookup"""
        count = 0
        url = f"https://iphostinfo.com/html/Reverse_IP_Lookup_{ip.replace('.', '_')}.html"
        
        try:
            await asyncio.sleep(2)
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [IPHostInfo] {domain}")

        except Exception as e:
            print(f"  [IPHostInfo] Error: {e}")

        return count

    async def source_domainbigdata(self, ip: str, limit: Optional[int] = None) -> int:
        """DomainBigData reverse IP lookup"""
        count = 0
        url = f"https://domainbigdata.com/sd/{ip}"
        
        try:
            await asyncio.sleep(2)
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            pattern = r'[a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,}'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [DomainBigData] {domain}")

        except Exception as e:
            print(f"  [DomainBigData] Error: {e}")

        return count

    async def source_myip(self, ip: str, limit: Optional[int] = None) -> int:
        """MyIP.ms reverse IP lookup"""
        count = 0
        url = f"https://myip.ms/browse/domains/{ip}"
        
        try:
            await asyncio.sleep(3)
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            pattern = r'([a-zA-Z0-9][-a-zA-Z0-9.]{1,61}\.[a-zA-Z]{2,})'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [MyIP.ms] {domain}")

        except Exception as e:
            print(f"  [MyIP.ms] Error: {e}")

        return count

    # ==================== Certificate Transparency Sources ====================

    async def source_crtsh(self, ip: str, limit: Optional[int] = None) -> int:
        """crt.sh certificate transparency search"""
        count = 0
        
        # First, try to get domain from PTR
        base_domains = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            ptr_answers = resolver.resolve(ip, 'PTR')
            if ptr_answers:
                ptr = str(ptr_answers[0]).rstrip('.')
                # Extract the base domain
                parts = ptr.split('.')
                if len(parts) >= 2:
                    base_domains.append('.'.join(parts[-2:]))
        except:
            pass
        
        # Search for each base domain
        for base_domain in base_domains[:3]:  # Limit to 3 PTR results
            if limit and count >= limit:
                break
                
            url = f"https://crt.sh/?q=%.25252.{base_domain}&output=json"
            
            try:
                await asyncio.sleep(2)
                async with self.session.get(url) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()

                for cert in data:
                    if limit and count >= limit:
                        break
                    domain = cert['name_value'].strip()
                    # Handle wildcards
                    domain = domain.lstrip('*.')
                    if self.add_domain(domain):
                        count += 1
                        print(f"  [crt.sh] {domain}")

            except Exception as e:
                print(f"  [crt.sh] Error: {e}")

        return count

    async def source_censys(self, ip: str, limit: Optional[int] = None) -> int:
        """Censys search (requires API key for full results)"""
        count = 0
        api_id = self.api_keys.get('censys_api_id')
        api_secret = self.api_keys.get('censys_api_secret')
        
        if not api_id or not api_secret:
            print(f"  [Censys] Skipped - no API key provided")
            return 0
        
        url = "https://search.censys.io/api/v2/hosts/search"
        query = f"ip:{ip}"
        
        try:
            auth = aiohttp.BasicAuth(api_id, api_secret)
            await asyncio.sleep(1)
            
            async with self.session.post(url, auth=auth, json={"query": query, "per_page": 100}) as resp:
                if resp.status != 200:
                    return 0
                data = await resp.json()

            if 'result' in data and 'hits' in data['result']:
                for host in data['result']['hits']:
                    if limit and count >= limit:
                        break
                    if 'names' in host:
                        for domain in host['names']:
                            if self.add_domain(domain):
                                count += 1
                                print(f"  [Censys] {domain}")

        except Exception as e:
            print(f"  [Censys] Error: {e}")

        return count

    async def source_shodan(self, ip: str, limit: Optional[int] = None) -> int:
        """Shodan API (requires API key)"""
        count = 0
        api_key = self.api_keys.get('shodan_api_key')
        
        if not api_key:
            print(f"  [Shodan] Skipped - no API key provided")
            return 0
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        
        try:
            await asyncio.sleep(1)
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                data = await resp.json()

            if 'hostnames' in data:
                for hostname in data['hostnames']:
                    if limit and count >= limit:
                        break
                    if self.add_domain(hostname):
                        count += 1
                        print(f"  [Shodan] {hostname}")

        except Exception as e:
            print(f"  [Shodan] Error: {e}")

        return count

    async def source_zoomeye(self, ip: str, limit: Optional[int] = None) -> int:
        """ZoomEye API (requires API key)"""
        count = 0
        api_key = self.api_keys.get('zoomeye_api_key')
        
        if not api_key:
            print(f"  [ZoomEye] Skipped - no API key provided")
            return 0
        
        url = f"https://api.zoomeye.org/host/search?query=ip:{ip}"
        
        try:
            headers = {'API-KEY': api_key}
            await asyncio.sleep(1)
            
            async with self.session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return 0
                data = await resp.json()

            if 'matches' in data:
                for match in data['matches']:
                    if limit and count >= limit:
                        break
                    if 'geoinfo' in match and 'domains' in match['geoinfo']:
                        for domain in match['geoinfo']['domains']:
                            if self.add_domain(domain):
                                count += 1
                                print(f"  [ZoomEye] {domain}")

        except Exception as e:
            print(f"  [ZoomEye] Error: {e}")

        return count

    async def source_virustotal(self, ip: str, limit: Optional[int] = None) -> int:
        """VirusTotal API (requires API key)"""
        count = 0
        api_key = self.api_keys.get('virustotal_api_key')
        
        if not api_key:
            print(f"  [VirusTotal] Skipped - no API key provided")
            return 0
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        
        try:
            headers = {'x-apikey': api_key}
            await asyncio.sleep(1)
            
            async with self.session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return 0
                data = await resp.json()

            if 'data' in data and 'attributes' in data['data']:
                if 'last_dns_records' in data['data']['attributes']:
                    for record in data['data']['attributes']['last_dns_records']:
                        if record.get('type') == 'CNAME':
                            domain = record.get('value', '').rstrip('.')
                            if limit and count >= limit:
                                break
                            if self.add_domain(domain):
                                count += 1
                                print(f"  [VirusTotal] {domain}")

        except Exception as e:
            print(f"  [VirusTotal] Error: {e}")

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

    async def lookup(self, ip: str, sources: List[str] = None, limit: Optional[int] = None):
        """Perform reverse IP lookup"""
        print(f"\n🔍 Reverse IP Lookup: {ip}")
        print(f"{'='*50}\n")

        if sources is None:
            sources = ['dns-ptr', 'viewdns', 'bing', 'duckduckgo', 'netcraft', 
                      'yougetsignal', 'iphostinfo', 'domainbigdata', 'myip', 'crtsh']

        start_time = time.time()

        # Run all sources
        tasks = []
        for source in sources:
            source_method = getattr(self, f'source_{source}', None)
            if source_method:
                tasks.append(source_method(ip, limit))

        if tasks:
            results = await asyncio.gather(*tasks)
            total_found = sum(results)

        elapsed = time.time() - start_time

        print(f"\n{'='*50}")
        print(f"📊 Results:")
        print(f"   Total unique domains: {len(self.domains)}")
        print(f"   Time elapsed: {elapsed:.2f}s")
        print(f"   Sources used: {', '.join(sources)}")

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
        # Get the first A record
        ip = socket.gethostbyname(domain)
        return True, ip
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    except Exception as e:
        return False, f"Error: {e}"


async def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Reverse IP Lookup - Find all domains on an IP or from a domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s google.com
  %(prog)s 8.8.8.8 --limit 50
  %(prog)s google.com --sources viewdns bing crtsh --output results.json
  %(prog)s 8.8.8.8 --format json --output domains.json

DNS Sources:
  dns-ptr      - DNS PTR record lookup
  dns-bruteforce - Common subdomain enumeration
  host         - System host command

Web Scraping Sources:
  viewdns      - ViewDNS.info (free, good coverage)
  bing         - Bing search (may find more)
  duckduckgo   - DuckDuckGo search
  netcraft     - Netcraft site report
  yougetsignal - YouGetSignal reverse lookup
  iphostinfo   - IPHostInfo domains
  domainbigdata - DomainBigData lookup
  myip         - MyIP.ms reverse IP

Certificate Sources:
  crtsh        - Certificate Transparency logs

API Sources (requires API keys):
  censys       - Censys API (--censys-api-id and --censys-api-secret)
  shodan       - Shodan API (--shodan-api-key)
  zoomeye      - ZoomEye API (--zoomeye-api-key)
  virustotal   - VirusTotal API (--virustotal-api-key)

API Key Configuration:
  Pass API keys via command line or environment variables:
  CENSYS_API_ID, CENSYS_API_SECRET
  SHODAN_API_KEY
  ZOOMEYE_API_KEY
  VIRUSTOTAL_API_KEY
        """
    )

    parser.add_argument('target', help='IP address or domain to lookup')
    parser.add_argument('--limit', '-l', type=int,
                        help='Limit number of results (default: unlimited)')
    parser.add_argument('--output', '-o', type=str,
                        help='Output file path (default: stdout)')
    parser.add_argument('--format', '-f', choices=['txt', 'json', 'csv'],
                        default='txt', help='Output format (default: txt)')
    parser.add_argument('--sources', '-s', nargs='+',
                        choices=['dns-ptr', 'dns-bruteforce', 'host', 'viewdns', 'bing', 
                                'duckduckgo', 'netcraft', 'yougetsignal', 'iphostinfo', 
                                'domainbigdata', 'myip', 'crtsh', 'censys', 'shodan', 
                                'zoomeye', 'virustotal'],
                        help='Data sources to use (default: all non-API sources)')
    
    # API Key arguments
    parser.add_argument('--censys-api-id', type=str, 
                        help='Censys API ID (or set CENSYS_API_ID env var)')
    parser.add_argument('--censys-api-secret', type=str,
                        help='Censys API Secret (or set CENSYS_API_SECRET env var)')
    parser.add_argument('--shodan-api-key', type=str,
                        help='Shodan API Key (or set SHODAN_API_KEY env var)')
    parser.add_argument('--zoomeye-api-key', type=str,
                        help='ZoomEye API Key (or set ZOOMEYE_API_KEY env var)')
    parser.add_argument('--virustotal-api-key', type=str,
                        help='VirusTotal API Key (or set VIRUSTOTAL_API_KEY env var)')

    args = parser.parse_args()

    # Collect API keys from args or environment
    api_keys = {
        'censys_api_id': args.censys_api_id or os.environ.get('CENSYS_API_ID'),
        'censys_api_secret': args.censys_api_secret or os.environ.get('CENSYS_API_SECRET'),
        'shodan_api_key': args.shodan_api_key or os.environ.get('SHODAN_API_KEY'),
        'zoomeye_api_key': args.zoomeye_api_key or os.environ.get('ZOOMEYE_API_KEY'),
        'virustotal_api_key': args.virustotal_api_key or os.environ.get('VIRUSTOTAL_API_KEY'),
    }

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
    async with ReverseLookup(args.output, args.format, api_keys) as lookup:
        domains = await lookup.lookup(target_ip, args.sources, args.limit)

    # Print summary
    if not args.output or args.format == 'txt':
        print(f"\n{'='*50}")
        print(f"🔢 Domains found: {len(domains)}")
        if len(domains) <= 100:
            print(f"\n{chr(10).join(sorted(domains))}")


if __name__ == '__main__':
    asyncio.run(main())
