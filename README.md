# Reverse IP Lookup Tool - Pure DNS Version

**Pure DNS reverse IP lookup** to find all domains hosted on a specific IP address or from a domain name. Uses only DNS queries and system commands - no external data sources, APIs, or web scraping required.

## Features

- 🔒 **100% DNS-based** - Only uses DNS queries and system commands
- ⚡ **Fast & Private** - No external requests, no rate limits
- 🎯 **8 DNS sources** - PTR, MX, NS, TXT, SRV, and more
- 🧩 **Domain support** - Auto-resolves domains to IPs
- 🔄 **Subdomain bruteforce** - 60+ common subdomains
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- 📦 **Zero dependencies** - Only dnspython required
- 📱 **Termux compatible** - Works on Android via Termux

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
# Lookup an IP address
python main.py 8.8.8.8

# Lookup a domain (resolves to IP first)
python main.py google.com

# Save results to file
python main.py 8.8.8.8 --output results.txt

# Save as JSON
python main.py google.com --format json --output results.json

# Save as CSV
python main.py 8.8.8.8 --format csv --output results.csv
```

## Named Arguments

| Argument | Short | Type | Description |
|----------|-------|------|-------------|
| `target` | - | str | **Required** - IP address or domain to lookup |
| `--output` | `-o` | str | Output file path (default: stdout) |
| `--format` | `-f` | str | Output format: txt, json, csv (default: txt) |

## DNS Sources (All sources are used automatically)

| Source | Description | What it finds |
|--------|-------------|---------------|
| **DNS-PTR** | DNS PTR record lookup | Primary reverse DNS record |
| **Host** | System host command | Native DNS lookup |
| **Nslookup** | System nslookup command | Standard DNS lookup |
| **DNS-MX** | DNS MX records | Mail server domains |
| **DNS-NS** | DNS NS records | Name server domains |
| **DNS-TXT** | DNS TXT records | Domains in TXT records |
| **DNS-SRV** | DNS SRV records | Service-related domains |
| **Brute-Force** | Subdomain enumeration | Common subdomains |

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

### Save to File

```bash
# Save as TXT
python main.py example.com --output domains.txt

# Save as JSON
python main.py example.com --format json --output domains.json

# Save as CSV
python main.py example.com --format csv --output domains.csv
```

## How It Works

1. **Input**: IP address or domain name
2. **Domain Resolution**: If domain is provided, resolves to IP using DNS
3. **DNS Queries**: Runs all 8 DNS sources automatically
4. **Subdomain Brute Force**: Tests 60+ common subdomains against PTR domain
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

## Subdomain Bruteforce

The bruteforce source tests 60+ common subdomains:

**Infrastructure**: www, mail, ftp, admin, api, dev, test, staging

**Services**: blog, shop, store, forum, wiki, help, support, docs

**Tech Stack**: cdn, static, assets, img, images, video, media, upload

**Mail**: pop, imap, smtp, exchange, webmail, mail, email

**Systems**: ns1, ns2, ns3, mx, lb, proxy, firewall, gateway

**DevOps**: db, database, cache, lb, master, slave, worker

## Requirements

- Python 3.7+
- dnspython

## Termux Support

This tool is fully compatible with Termux on Android. It automatically detects if `/etc/resolv.conf` is not available (as in Termux) and falls back to public DNS servers (Google DNS, Cloudflare DNS).

For detailed Termux installation and troubleshooting, see [TERMUX.md](TERMUX.md).

To use on Termux:

```bash
# Install dnspython
pkg install python-pip
pip install dnspython

# Run the tool
python main.py google.com
```

## Advantages of Pure DNS Approach

✅ **No external dependencies** - Only DNS queries
✅ **No rate limiting** - No API limits
✅ **Fast** - Direct DNS queries are quick
✅ **Private** - No data shared with third parties
✅ **Reliable** - Uses standard DNS protocols
✅ **No authentication** - No API keys needed
✅ **Offline capable** - Works with local DNS
✅ **Cross-platform** - Works on Linux, macOS, Windows, Termux

## Limitations

⚠️ **Only finds PTR-mapped domains** - Can't find domains without PTR records
⚠️ **Depends on DNS configuration** - Results vary by server
⚠️ **Bruteforce limited** - Only tests common subdomains
⚠️ **Requires DNS records** - Needs proper DNS configuration

## Tips

- **Quick lookup**: Just run `python main.py <ip_or_domain>`
- **Save results**: Use `--output` flag to save to file
- **Different formats**: Use `--format json` or `--format csv`
- **No sources to choose**: All 8 DNS sources run automatically

## Troubleshooting

### DNS Resolution Issues
```bash
# Test DNS resolution
python main.py google.com
# If fails, check your internet connection
```

### No PTR Record Found
```
# This is normal for many IPs
# Not all IPs have reverse DNS configured
```

### Bruteforce Returns No Results
```
# The domain might not use common subdomain patterns
# Results will still include domains from other DNS sources
```

## License

MIT

## Contributing

Pull requests welcome! Add more DNS query types or improve existing ones.

## Credits

Built with Python and dnspython. Pure DNS-based approach with no external dependencies.
