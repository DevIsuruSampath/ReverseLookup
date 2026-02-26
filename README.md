# Reverse IP Lookup Tool - Pure DNS Version

**Pure DNS reverse IP lookup** to find all domains hosted on a specific IP address or from a domain name. Uses only DNS queries and system commands - no external data sources, APIs, or web scraping required.

## Features

- 🔒 **100% DNS-based** - Only uses DNS queries and system commands
- ⚡ **Fast & Private** - No external requests, no rate limits
- 🎯 **12+ DNS sources** - PTR, MX, NS, TXT, SRV, CNAME, AXFR, and more
- 🧩 **Domain support** - Auto-resolve domains to IPs
- 🔄 **Subdomain bruteforce** - 100+ common subdomains
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- 📦 **Zero dependencies** - Only dnspython required

## Installation

```bash
# Clone or navigate to the directory
cd ReverseLookup

# Install dependencies
pip install -r requirements.txt

# Or install directly
pip install dnspython
```

## Usage

### Basic Usage

```bash
# Unlimited lookup for an IP
python main.py 8.8.8.8

# Unlimited lookup for a domain (resolves to IP first)
python main.py google.com

# Limit results to 50 domains
python main.py 8.8.8.8 --limit 50

# Use specific DNS sources only
python main.py 8.8.8.8 --sources dns-ptr host bruteforce
```

### Output Options

```bash
# Save to TXT file
python main.py 8.8.8.8 --output results.txt

# Save to JSON file
python main.py 8.8.8.8 --format json --output results.json

# Save to CSV file
python main.py 8.8.8.8 --format csv --output results.csv
```

### Combined Options

```bash
# Find up to 100 domains using DNS PTR, host command, and bruteforce, save as JSON
python main.py 8.8.8.8 --limit 100 --sources dns-ptr host bruteforce --format json --output results.json

# Unlimited search with all DNS sources
python main.py 1.1.1.1 --output domains.txt

# Domain lookup with comprehensive DNS sources
python main.py google.com --sources dns-ptr dns-mx dns-ns dns-txt bruteforce
```

## Named Arguments

| Argument | Short | Type | Description |
|----------|-------|------|-------------|
| `target` | - | str | **Required** - IP address or domain to lookup |
| `--limit` | `-l` | int | Limit number of results (default: unlimited) |
| `--output` | `-o` | str | Output file path (default: stdout) |
| `--format` | `-f` | str | Output format: txt, json, csv (default: txt) |
| `--sources` | `-s` | list | DNS sources to use (default: dns-ptr, host, bruteforce, dns-mx, dns-ns, dns-txt, dns-srv) |

## DNS Sources

### Primary DNS Sources

| Source | Description | Speed | Notes |
|--------|-------------|-------|-------|
| **dns-ptr** | DNS PTR record lookup | ⚡⚡⚡ | Primary reverse DNS record |
| **host** | System host command | ⚡⚡⚡ | Native DNS lookup |
| **dig** | System dig command | ⚡⚡⚡ | Advanced DNS tool |
| **nslookup** | System nslookup command | ⚡⚡ | Standard DNS lookup |

### Record Type Sources

| Source | Description | Speed | What it finds |
|--------|-------------|-------|---------------|
| **dns-mx** | DNS MX records | ⚡⚡ | Mail server domains |
| **dns-ns** | DNS NS records | ⚡⚡ | Name server domains |
| **dns-txt** | DNS TXT records | ⚡⚡ | Domains in TXT records |
| **dns-any** | DNS ANY record | ⚡⚡ | All available records |
| **dns-srv** | DNS SRV records | ⚡ | Service-related domains |
| **dns-cname** | DNS CNAME chain | ⚡ | Alias/redirect domains |

### Advanced Sources

| Source | Description | Speed | Notes |
|--------|-------------|-------|-------|
| **dns-axfr** | DNS Zone Transfer | ⚡ | If AXFR is allowed (rare) |
| **bruteforce** | Subdomain enumeration | ⚡⚡ | Tests 100+ common subdomains |

## Output Formats

### TXT (default)
```
google.com
mail.google.com
analytics.google.com
...
Total: 15 domains
```

### JSON
```json
{
  "domains": ["google.com", "mail.google.com", ...],
  "total": 15
}
```

### CSV
```csv
domain
google.com
mail.google.com
...
```

## Examples

### Quick Lookups

```bash
# Common DNS servers
python main.py 8.8.8.8      # Google DNS
python main.py 1.1.1.1      # Cloudflare DNS
python main.py 9.9.9.9      # Quad9 DNS

# Popular domains
python main.py google.com
python main.py facebook.com
python main.py amazon.com
```

### Research & Security

```bash
# Find all domains on an IP using all DNS sources
python main.py 192.0.2.1 --output all-dns.txt

# Bruteforce subdomains
python main.py example.com --sources dns-ptr bruteforce --limit 100

# Check mail and name servers
python main.py example.com --sources dns-mx dns-ns
```

### Comprehensive Search

```bash
# Use all available DNS sources
python main.py 1.1.1.1 --sources dns-ptr dns-mx dns-ns dns-txt dns-srv dns-cname bruteforce host dig nslookup
```

## How It Works

1. **Input**: IP address or domain name
2. **Domain Resolution**: If domain is provided, resolves to IP using DNS
3. **DNS Queries**: Runs selected DNS query types
4. **Subdomain Brute Force**: Tests common subdomains against the PTR domain
5. **Result Collection**: Aggregates domains from all DNS queries
6. **Output**: Formats and saves results

## DNS Query Types Explained

### PTR Record
- The primary reverse DNS record
- Maps IP address to domain name
- Example: `8.8.8.8` → `dns.google`

### MX Record
- Mail Exchange records
- Find mail server domains
- Example: `mx.google.com`, `smtp.gmail.com`

### NS Record
- Name Server records
- Find nameserver domains
- Example: `ns1.google.com`, `ns2.google.com`

### TXT Record
- Text records (often contain verification info)
- May contain domain references
- Example: SPF records, DKIM records

### SRV Record
- Service records
- Find service-specific domains
- Example: `_xmpp-server._tcp.google.com`

### CNAME Record
- Canonical Name (alias) records
- Find aliased/redirect domains
- Example: `www.google.com` → `google.com`

### AXFR (Zone Transfer)
- Full zone dump (if allowed)
- Can find all domains in a zone
- Usually disabled for security

## Subdomain Bruteforce

The bruteforce source tests 100+ common subdomains:

**Infrastructure**: www, mail, ftp, admin, api, dev, test, staging, production

**Services**: blog, shop, store, forum, wiki, help, support, docs

**Tech Stack**: cdn, static, assets, img, images, video, media, upload, db, cache

**Mail**: pop, imap, smtp, exchange, webmail, mail, email

**Systems**: ns1, ns2, ns3, mx, lb, proxy, firewall, gateway

**DevOps**: jenkins, gitlab, nexus, docker, k8s, kubernetes, consul, vault

**Monitoring**: grafana, prometheus, kibana, elasticsearch, log, metrics

**And many more...**

## Requirements

- Python 3.7+
- dnspython

## Advantages of Pure DNS Approach

✅ **No external dependencies** - Only DNS queries
✅ **No rate limiting** - No API limits
✅ **Fast** - Direct DNS queries are quick
✅ **Private** - No data shared with third parties
✅ **Reliable** - Uses standard DNS protocols
✅ **No authentication** - No API keys needed
✅ **Offline capable** - Works with local DNS

## Limitations

⚠️ **Only finds PTR-mapped domains** - Can't find domains without PTR records
⚠️ **Depends on DNS configuration** - Results vary by server
⚠️ **Bruteforce limited** - Only tests common subdomains
⚠️ **AXFR rare** - Zone transfers are usually disabled

## Tips

- **Start fast**: Use `dns-ptr` and `host` for quick results
- **Deep search**: Add `bruteforce` for subdomains
- **Mail servers**: Use `dns-mx` to find email domains
- **Name servers**: Use `dns-ns` to find DNS server domains
- **Services**: Use `dns-srv` for service-related domains
- **Combine sources**: Use multiple sources for best coverage

## Troubleshooting

### DNS Resolution Issues
```bash
# Test DNS resolution
python main.py google.com
# If fails, check your DNS server
```

### No PTR Record Found
```
# This is normal for many IPs
# Not all IPs have reverse DNS configured
```

### Bruteforce Returns No Results
```
# The domain might not use common subdomain patterns
# Try different sources like dns-mx, dns-ns
```

## Comparison with Web Scraping Version

| Feature | Pure DNS Version | Web Scraping Version |
|---------|------------------|---------------------|
| External requests | No | Yes |
| Rate limits | No | Yes |
| API keys | No | Optional |
| Speed | Fast | Slower |
| Privacy | High | Medium |
| Coverage | Medium | High |
| Dependencies | dnspython | aiohttp, dnspython |

## License

MIT

## Contributing

Pull requests welcome! Add more DNS query types or improve existing ones.

## Credits

Built with Python and dnspython. Pure DNS-based approach with no external dependencies.
