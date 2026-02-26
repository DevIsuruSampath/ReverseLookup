# Usage Examples

## Example 1: Basic IP Lookup

```bash
$ python main.py 8.8.8.8 --limit 10

📍 Target: 8.8.8.8 (IP address)

🔍 Reverse IP Lookup: 8.8.8.8
==================================================

  [ViewDNS] dns.google
  [Netcraft] dns.google

==================================================
📊 Results:
   Total unique domains: 1
   Time elapsed: 3.2s
   Sources used: viewdns, netcraft

==================================================
🔢 Domains found: 1

dns.google
```

## Example 2: Domain Lookup

```bash
$ python main.py google.com --sources dns-ptr viewdns crtsh --limit 20

🔗 Resolving domain: google.com
✅ Resolved to: 142.250.80.46

🔍 Reverse IP Lookup: 142.250.80.46
==================================================

  [DNS-PTR] dns.google
  [ViewDNS] google.com
  [ViewDNS] www.google.com
  [ViewDNS] mail.google.com
  [crt.sh] google.com
  [crt.sh] www.google.com
  [crt.sh] *.google.com
  [crt.sh] accounts.google.com

==================================================
📊 Results:
   Total unique domains: 8
   Time elapsed: 8.5s
   Sources used: dns-ptr, viewdns, crtsh

==================================================
🔢 Domains found: 8

accounts.google.com
dns.google
google.com
mail.google.com
www.google.com
```

## Example 3: Multiple Web Sources

```bash
$ python main.py example.com --sources viewdns bing duckduckgo netcraft --format json --output results.json

🔗 Resolving domain: example.com
✅ Resolved to: 93.184.216.34

🔍 Reverse IP Lookup: 93.184.216.34
==================================================

  [ViewDNS] example.com
  [ViewDNS] www.example.com
  [Bing] example.com
  [Bing] www.example.com
  [DuckDuckGo] example.com
  [Netcraft] example.com
  [Netcraft] www.example.com

==================================================
📊 Results:
   Total unique domains: 2
   Time elapsed: 12.3s
   Sources used: viewdns, bing, duckduckgo, netcraft

✅ Saved 2 domains to results.json
```

## Example 4: With API Sources

```bash
$ export SHODAN_API_KEY="your_api_key"
$ python main.py 1.1.1.1 --sources dns-ptr shodan crtsh --limit 50

📍 Target: 1.1.1.1 (IP address)

🔍 Reverse IP Lookup: 1.1.1.1
==================================================

  [DNS-PTR] one.one.one.one
  [Shodan] one.one.one.one
  [Shodan] 1.1.1.1
  [crt.sh] one.one.one.one
  [crt.sh] *.one.one.one.one

==================================================
📊 Results:
   Total unique domains: 2
   Time elapsed: 4.2s
   Sources used: dns-ptr, shodan, crtsh

==================================================
🔢 Domains found: 2

one.one.one.one
```

## Example 5: CSV Output

```bash
$ python main.py 8.8.8.8 --format csv --output results.csv --limit 10

📍 Target: 8.8.8.8 (IP address)

🔍 Reverse IP Lookup: 8.8.8.8
==================================================

  [ViewDNS] dns.google

==================================================
📊 Results:
   Total unique domains: 1
   Time elapsed: 2.1s
   Sources used: viewdns

✅ Saved 1 domains to results.csv
```

## Example 6: All Free Sources

```bash
$ python main.py example.com --output all-results.txt

🔗 Resolving domain: example.com
✅ Resolved to: 93.184.216.34

🔍 Reverse IP Lookup: 93.184.216.34
==================================================

  [DNS-PTR] example.com
  [ViewDNS] example.com
  [ViewDNS] www.example.com
  [Bing] example.com
  [DuckDuckGo] example.com
  [Netcraft] example.com
  [Netcraft] www.example.com
  [YouGetSignal] example.com
  [crt.sh] example.com
  [crt.sh] www.example.com

==================================================
📊 Results:
   Total unique domains: 4
   Time elapsed: 25.8s
   Sources used: dns-ptr, viewdns, bing, duckduckgo, netcraft, yougetsignal, iphostinfo, domainbigdata, myip, crtsh

✅ Saved 4 domains to all-results.txt
```

## Tips for Best Results

1. **Start with DNS sources** (`dns-ptr`, `host`) for quick results
2. **Add web scraping** (`viewdns`, `bing`, `crtsh`) for more domains
3. **Use API sources** (`shodan`, `censys`) for comprehensive results
4. **Combine multiple sources** for best coverage
5. **Use `--limit`** to cap results and speed up searches
6. **Save to JSON** for programmatic processing
