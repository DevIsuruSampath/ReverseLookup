# Reverse IP Lookup Tool - Simple Fast Version

**Simple fast reverse IP lookup** using ONLY Linux CLI tools and Python DNS libraries. No external APIs, no web scraping, no Certificate Transparency.

## Features

- ⚡ **Very Fast** - Completes in <10 seconds
- 🛡️ **Linux CLI tools** - host, dig, nslookup, whois
- 📦 **Python DNS** - PTR lookup
- 🎯 **Simple** - No external dependencies
- 🧩 **Domain support** - Auto-resolves domains to IPs
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- 📦 **Minimal dependencies** - Only dnspython required
- 📱 **Cross-platform** - Linux, Kali, Termux, macOS, Windows

## Installation

```bash
# Clone or navigate to directory
cd ReverseLookup

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Lookup an IP address
python main.py 8.8.8.8

# Lookup a domain
python main.py google.com

# Save results to file
python main.py 8.8.8.8 --output results.txt

# JSON format
python main.py google.com --format json --output domains.json
```

## Linux CLI Tools Used

| Tool | Description | Check |
|------|-------------|-------|
| **host** | DNS lookup tool | `which host` |
| **dig** | Advanced DNS tool | `which dig` |
| **nslookup** | DNS lookup tool | `which nslookup` |
| **whois** | WHOIS client | `which whois` |

## Python Libraries Used

| Library | Description | Required |
|---------|-------------|----------|
| **dnspython** | DNS resolver | Yes |

## Data Sources

| Source | Type | Description |
|--------|------|-------------|
| **host** | Linux CLI | DNS PTR lookup |
| **dig** | Linux CLI | Reverse DNS lookup |
| **nslookup** | Linux CLI | DNS name server lookup |
| **whois** | Linux CLI | Domain ownership information |
| **dns-ptr** | Python DNS | Python PTR record lookup |

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
python main.py 8.8.8.8
python main.py 1.1.1.1
python main.py 9.9.9.9

# Popular domains
python main.py google.com
python main.py facebook.com
python main.py viber.com
python main.py dialog.lk
```

### Save to File

```bash
# Save as TXT
python main.py 8.8.8.8 --output results.txt

# Save as JSON
python main.py google.com --format json --output google.json

# Save as CSV
python main.py 1.1.1.1 --format csv --output domains.csv
```

## How It Works

1. **Input**: IP address or domain name
2. **Resolution**: If domain, resolves to IP using DNS
3. **Linux CLI Tools**: Runs host, dig, nslookup, whois (5s timeout each)
4. **Python DNS**: Runs PTR lookup using dnspython
5. **Aggregation**: Collects all unique domains
6. **Filtering**: Removes registry and abuse domains
7. **Output**: Formats and saves results

## Performance

| Source | Time | Description |
|--------|-------|-------------|
| **host** | ~2s | DNS PTR lookup |
| **dig** | ~1s | Reverse DNS lookup |
| **nslookup** | ~2s | DNS name server lookup |
| **whois** | ~3s | Domain ownership info |
| **dns-ptr** | ~1s | Python PTR lookup |
| **Total** | **~5-9s** | All sources |

## Smart Filtering

The tool automatically filters out:

- **Registry domains**: arin.net, rdap.arin.net, ripe.net, apnic.net, lacnic.net, afrinic.net
- **Abuse domains**: abuse.net, dis.abuse, knock.black

## Advantages

✅ **Very Fast** - Completes in <10 seconds
✅ **No External APIs** - Uses only local tools
✅ **No Rate Limits** - No external service dependencies
✅ **No Web Scraping** - No HTTP requests to external sites
✅ **No Certificate Transparency** - No CT log queries
✅ **Simple & Reliable** - Uses proven Linux CLI tools
✅ **Privacy** - No data shared with third parties
✅ **Cross-platform** - Works on Linux, Kali, Termux, macOS, Windows

## Requirements

- Python 3.7+
- dnspython

## Tips

- **Fast lookup**: Just run the tool, all sources run automatically
- **Quick scan**: Uses timeout of 5s per tool for speed
- **Save results**: Use `--output` flag to save to file
- **JSON for automation**: Use `--format json` for programmatic use

## Troubleshooting

### Tools Not Found

```
# Install Linux CLI tools on Debian/Ubuntu/Kali:
sudo apt install -y dnsutils whois

# On Termux (Android):
pkg install dnsutils whois
```

### No Domains Found

```
# Some IPs don't have PTR records
# This is normal
```

### Domain Resolution Failed

```
# Check your internet connection
# Or try using the IP directly instead of domain
```

## License

MIT

## Contributing

Pull requests welcome!

## Credits

Built with Python, dnspython, and Linux CLI tools (host, dig, nslookup, whois).
