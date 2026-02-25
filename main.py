#!/usr/bin/env python3
"""
Reverse IP Lookup Tool
Find all domains hosted on a specific IP address
"""

import argparse
import asyncio
import aiohttp
import json
import re
import sys
from typing import List, Set, Optional
from urllib.parse import quote, urlencode
import time


class ReverseLookup:
    """Reverse IP lookup using multiple sources"""

    def __init__(self, output_file: Optional[str] = None, output_format: str = 'txt'):
        self.domains: Set[str] = set()
        self.output_file = output_file
        self.output_format = output_format
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
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
            if clean not in self.domains:
                self.domains.add(clean)
                return True
        return False

    async def source_viewdns(self, ip: str, limit: Optional[int] = None) -> int:
        """ViewDNS.info API (free with rate limiting)"""
        url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
        count = 0

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Parse HTML response
            pattern = r'<td>([^<]+\.[^<]+)</td>'
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
        max_pages = 10 if not limit else min(10, (limit // 10) + 1)

        for page in range(max_pages):
            if limit and count >= limit:
                break

            offset = page * 10
            query = f"ip:{ip}"
            url = f"https://www.bing.com/search?q={quote(query)}&first={offset}"

            try:
                await asyncio.sleep(1)  # Rate limiting
                async with self.session.get(url) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text()

                # Extract domains from search results
                pattern = r'https?://([^/<>"\'\s]+)'
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

    async def source_censys(self, ip: str, limit: Optional[int] = None) -> int:
        """Censys search (limited free tier)"""
        count = 0
        # Censys requires API key, this uses public search page
        url = f"https://search.censys.io/search?q=services.ip_address:{ip}"

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Parse for domain names
            pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.[a-zA-Z]{2,})'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [Censys] {domain}")

        except Exception as e:
            print(f"  [Censys] Error: {e}")

        return count

    async def source_shodan(self, ip: str, limit: Optional[int] = None) -> int:
        """Shodan public search (limited)"""
        count = 0
        url = f"https://www.shodan.io/search?query={quote(ip)}"

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Extract hostnames
            pattern = r'hostname:\s*([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})'
            matches = re.findall(pattern, text)

            for domain in matches:
                if limit and count >= limit:
                    break
                if self.add_domain(domain):
                    count += 1
                    print(f"  [Shodan] {domain}")

        except Exception as e:
            print(f"  [Shodan] Error: {e}")

        return count

    async def source_netcraft(self, ip: str, limit: Optional[int] = None) -> int:
        """Netcraft site report"""
        count = 0
        url = f"https://searchdns.netcraft.com/?restriction=site+contains&host={quote(ip)}"

        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return 0
                text = await resp.text()

            # Parse domains
            pattern = r'<a[^>]*href="https?://([^/"\'<>]+)"'
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
            sources = ['viewdns', 'bing', 'censys', 'shodan', 'netcraft']

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


async def main():
    parser = argparse.ArgumentParser(
        description='Reverse IP Lookup - Find all domains on an IP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8
  %(prog)s 8.8.8.8 --limit 50
  %(prog)s 8.8.8.8 --sources viewdns bing --output results.json
  %(prog)s 8.8.8.8 --format json --output domains.json

Sources:
  viewdns  - ViewDNS.info (free, good coverage)
  bing     - Bing search (may find more)
  censys   - Censys (limited free tier)
  shodan   - Shodan (limited free tier)
  netcraft - Netcraft site report
        """
    )

    parser.add_argument('ip', help='IP address to lookup')
    parser.add_argument('--limit', '-l', type=int,
                        help='Limit number of results (default: unlimited)')
    parser.add_argument('--output', '-o', type=str,
                        help='Output file path (default: stdout)')
    parser.add_argument('--format', '-f', choices=['txt', 'json', 'csv'],
                        default='txt', help='Output format (default: txt)')
    parser.add_argument('--sources', '-s', nargs='+',
                        choices=['viewdns', 'bing', 'censys', 'shodan', 'netcraft'],
                        help='Data sources to use (default: all)')

    args = parser.parse_args()

    # Validate IP
    if not validate_ip(args.ip):
        print(f"❌ Invalid IP address: {args.ip}")
        sys.exit(1)

    # Perform lookup
    async with ReverseLookup(args.output, args.format) as lookup:
        domains = await lookup.lookup(args.ip, args.sources, args.limit)

    # Print summary
    if not args.output or args.format == 'txt':
        print(f"\n{'='*50}")
        print(f"🔢 Domains found: {len(domains)}")
        if len(domains) <= 100:
            print(f"\n{''.join(sorted(domains))}")


if __name__ == '__main__':
    asyncio.run(main())
