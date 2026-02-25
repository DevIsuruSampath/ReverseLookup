# Reverse IP Lookup Tool

Unlimited reverse IP lookup to find all domains hosted on a specific IP address or from a domain name.

## Features

- 🚀 **Unlimited mode** - Find all possible domains (limited by sources)
- 📊 **Multiple data sources** - ViewDNS, Bing, Censys, Shodan, Netcraft
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- ⚡ **Fast & async** - Uses asyncio for concurrent lookups
- 🎯 **Selective sources** - Choose which data sources to use
- 📝 **Optional limits** - Limit results when needed

## Installation

```bash
# Clone or navigate to the directory
cd ReverseLookup

# Install dependencies
pip install -r requirements.txt
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

# Use specific sources only
python main.py 8.8.8.8 --sources viewdns bing
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
# Find up to 100 domains using ViewDNS and Bing, save as JSON
python main.py 8.8.8.8 --limit 100 --sources viewdns bing --format json --output results.json

# Unlimited search, all sources, output to file
python main.py 1.1.1.1 --output domains.txt
```

## Named Arguments

| Argument | Short | Type | Description |
|----------|-------|------|-------------|
| `target` | - | str | **Required** - IP address or domain to lookup |
| `--limit` | `-l` | int | Limit number of results (default: unlimited) |
| `--output` | `-o` | str | Output file path (default: stdout) |
| `--format` | `-f` | str | Output format: txt, json, csv (default: txt) |
| `--sources` | `-s` | list | Data sources: viewdns, bing, censys, shodan, netcraft |

## Data Sources

| Source | Coverage | Rate Limit | Notes |
|--------|----------|------------|-------|
| **viewdns** | High | Medium | Free API, good initial results |
| **bing** | Medium | Low | Search-based, may find more |
| **censys** | High | Low | Limited free tier |
| **shodan** | Medium | Low | Limited free tier |
| **netcraft** | Medium | Medium | Site report data |

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

```bash
# Quick lookup of common DNS servers
python main.py 8.8.8.8      # Google DNS
python main.py 1.1.1.1      # Cloudflare DNS
python main.py 9.9.9.9      # Quad9 DNS

# Lookup by domain name
python main.py google.com
python main.py facebook.com --limit 50

# Research - Find all domains on suspicious IP
python main.py 192.0.2.1 --limit 200 --output suspicious.txt

# SEO analysis - Check competitor hosting
python main.py 203.0.113.1 --sources viewdns bing --format json --output competitor.json

# Security - Scan for phishing domains on same IP
python main.py 198.51.100.1 --output scan.txt
```

## Requirements

- Python 3.7+
- aiohttp

## Notes

- **Rate limiting**: Some sources have rate limits; the tool includes delays to avoid blocking
- **Accuracy**: Results vary by source and IP; combine multiple sources for best coverage
- **Privacy**: This tool uses public data sources only
- **Legal**: Use responsibly and only on IPs you have permission to investigate

## License

MIT

## Contributing

Pull requests welcome! Add more data sources or improve existing ones.
