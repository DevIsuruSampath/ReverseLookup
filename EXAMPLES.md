# Usage Examples - Pure DNS Version

## Example 1: Basic IP Lookup

```bash
$ python main.py 8.8.8.8

📍 Target: 8.8.8.8 (IP address)

🔍 Reverse IP Lookup: 8.8.8.8
==================================================

  [DNS-PTR] dns.google
  [Host] dns.google

==================================================
📊 Results:
   Total unique domains: 1
   Time elapsed: 0.2s
   Sources used: dns-ptr, host, bruteforce, dns-mx, dns-ns, dns-txt, dns-srv

==================================================
🔢 Domains found: 1

dns.google
```

## Example 2: Domain Lookup

```bash
$ python main.py google.com --sources dns-ptr dns-mx dns-ns --limit 20

🔗 Resolving domain: google.com
✅ Resolved to: 142.250.80.46

🔍 Reverse IP Lookup: 142.250.80.46
==================================================

  [DNS-PTR] ams15s16-in-f14.1e100.net
  [DNS-MX] smtp.google.com
  [DNS-MX] alt1.aspmx.l.google.com
  [DNS-MX] alt2.aspmx.l.google.com
  [DNS-NS] ns1.google.com
  [DNS-NS] ns2.google.com
  [DNS-NS] ns3.google.com
  [DNS-NS] ns4.google.com

==================================================
📊 Results:
   Total unique domains: 8
   Time elapsed: 1.5s
   Sources used: dns-ptr, dns-mx, dns-ns

==================================================
🔢 Domains found: 8

alt1.aspmx.l.google.com
alt2.aspmx.l.google.com
ams15s16-in-f14.1e100.net
ns1.google.com
ns2.google.com
ns3.google.com
ns4.google.com
smtp.google.com
```

## Example 3: Subdomain Bruteforce

```bash
$ python main.py example.com --sources dns-ptr bruteforce --limit 30

🔗 Resolving domain: example.com
✅ Resolved to: 93.184.216.34

🔍 Reverse IP Lookup: 93.184.216.34
==================================================

  [DNS-PTR] example.com
  [Brute-Force] www.example.com
  [Brute-Force] mail.example.com
  [Brute-Force] ftp.example.com
  [Brute-Force] api.example.com
  [Brute-Force] blog.example.com
  [Brute-Force] shop.example.com

==================================================
📊 Results:
   Total unique domains: 7
   Time elapsed: 8.2s
   Sources used: dns-ptr, bruteforce

==================================================
🔢 Domains found: 7

api.example.com
blog.example.com
example.com
ftp.example.com
mail.example.com
shop.example.com
www.example.com
```

## Example 4: System Commands

```bash
$ python main.py 1.1.1.1 --sources host dig nslookup

📍 Target: 1.1.1.1 (IP address)

🔍 Reverse IP Lookup: 1.1.1.1
==================================================

  [Host] one.one.one.one
  [Dig] one.one.one.one

==================================================
📊 Results:
   Total unique domains: 1
   Time elapsed: 0.3s
   Sources used: host, dig, nslookup

==================================================
🔢 Domains found: 1

one.one.one.one
```

## Example 5: JSON Output

```bash
$ python main.py 8.8.8.8 --format json --output results.json --limit 10

📍 Target: 8.8.8.8 (IP address)

🔍 Reverse IP Lookup: 8.8.8.8
==================================================

  [DNS-PTR] dns.google
  [Host] dns.google

==================================================
📊 Results:
   Total unique domains: 1
   Time elapsed: 0.2s
   Sources used: dns-ptr, host, bruteforce, dns-mx, dns-ns, dns-txt, dns-srv

✅ Saved 1 domains to results.json
```

## Example 6: CSV Output

```bash
$ python main.py 8.8.8.8 --format csv --output results.csv

📍 Target: 8.8.8.8 (IP address)

🔍 Reverse IP Lookup: 8.8.8.8
==================================================

  [DNS-PTR] dns.google

==================================================
📊 Results:
   Total unique domains: 1
   Time elapsed: 0.2s
   Sources used: dns-ptr, host, bruteforce, dns-mx, dns-ns, dns-txt, dns-srv

✅ Saved 1 domains to results.csv
```

## Example 7: All DNS Sources

```bash
$ python main.py example.com --sources dns-ptr dns-mx dns-ns dns-txt dns-srv dns-cname dns-any bruteforce --output all-dns.txt

🔗 Resolving domain: example.com
✅ Resolved to: 93.184.216.34

🔍 Reverse IP Lookup: 93.184.216.34
==================================================

  [DNS-PTR] example.com
  [DNS-MX] mail.example.com
  [DNS-NS] ns1.example.com
  [DNS-NS] ns2.example.com
  [DNS-TXT] spf.example.com
  [DNS-SRV] _sip._tcp.example.com
  [DNS-SRV] _xmpp-server._tcp.example.com
  [Brute-Force] www.example.com
  [Brute-Force] mail.example.com
  [Brute-Force] api.example.com

==================================================
📊 Results:
   Total unique domains: 12
   Time elapsed: 15.8s
   Sources used: dns-ptr, dns-mx, dns-ns, dns-txt, dns-srv, dns-cname, dns-any, bruteforce

✅ Saved 12 domains to all-dns.txt
```

## Example 8: DNS SRV Records

```bash
$ python main.py google.com --sources dns-ptr dns-srv --limit 20

🔗 Resolving domain: google.com
✅ Resolved to: 142.250.80.46

🔍 Reverse IP Lookup: 142.250.80.46
==================================================

  [DNS-PTR] ams15s16-in-f14.1e100.net
  [DNS-SRV] _sip._tcp.google.com
  [DNS-SRV] _xmpp-server._tcp.google.com
  [DNS-SRV] _xmpp-client._tcp.google.com

==================================================
📊 Results:
   Total unique domains: 5
   Time elapsed: 1.8s
   Sources used: dns-ptr, dns-srv

==================================================
🔢 Domains found: 5

_xmpp-client._tcp.google.com
_xmpp-server._tcp.google.com
_sip._tcp.google.com
ams15s16-in-f14.1e100.net
```

## Tips for Best Results

1. **Start with DNS PTR** (`dns-ptr`) for primary reverse DNS
2. **Add system commands** (`host`, `dig`) for native lookups
3. **Use bruteforce** (`bruteforce`) for subdomain enumeration
4. **Check mail servers** (`dns-mx`) for email domains
5. **Find name servers** (`dns-ns`) for DNS server domains
6. **Use multiple sources** for comprehensive coverage

## Common Use Cases

### Quick Lookup
```bash
python main.py 8.8.8.8 --sources dns-ptr host
```

### Subdomain Discovery
```bash
python main.py example.com --sources dns-ptr bruteforce
```

### Email Server Discovery
```bash
python main.py example.com --sources dns-mx
```

### DNS Server Discovery
```bash
python main.py example.com --sources dns-ns
```

### Service Discovery
```bash
python main.py example.com --sources dns-srv
```

### Comprehensive Search
```bash
python main.py example.com --sources dns-ptr dns-mx dns-ns dns-txt dns-srv dns-cname bruteforce --output comprehensive.txt
```

## Notes

- Results depend on DNS server configuration
- Not all IPs have PTR records configured
- Subdomain bruteforce tests 100+ common patterns
- No external requests or APIs are used
- Results are limited to what DNS records contain
