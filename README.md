# Reverse IP Lookup Tool

Enhanced unlimited reverse IP lookup to find all domains hosted on a specific IP address or from a domain name. Uses multiple data sources including DNS queries, web scraping, certificate transparency logs, and API integrations.

## Features

- 🚀 **Unlimited mode** - Find all possible domains (limited by sources)
- 📊 **15+ data sources** - DNS, web scraping, CT logs, and APIs
- 🎯 **Selective sources** - Choose which data sources to use
- 🔑 **API support** - Censys, Shodan, ZoomEye, VirusTotal
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- ⚡ **Fast & async** - Uses asyncio for concurrent lookups
- 🧩 **Domain support** - Auto-resolve domains to IPs
- 🛡️ **Smart filtering** - Automatically filters common false positives

## Installation

```bash
# Clone or navigate to the directory
cd ReverseLookup

# Install dependencies
pip install -r requirements.txt

# Or install directly
pip install aiohttp dnspython
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
python main.py 8.8.8.8 --sources viewdns bing crtsh
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

### API Key Configuration

API keys can be passed via command line or environment variables:

```bash
# Command line
python main.py 8.8.8.8 --shodan-api-key YOUR_KEY --censys-api-id ID --censys-api-secret SECRET

# Environment variables
export SHODAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export ZOOMEYE_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"

python main.py 8.8.8.8 --sources shodan censys
```

### Combined Options

```bash
# Find up to 100 domains using ViewDNS, Bing, and CRT.sh, save as JSON
python main.py 8.8.8.8 --limit 100 --sources viewdns bing crtsh --format json --output results.json

# Unlimited search with all non-API sources
python main.py 1.1.1.1 --output domains.txt

# Domain lookup with API sources
python main.py google.com --sources dns-ptr crtsh shodan zoomeye --shodan-api-key KEY --zoomeye-api-key KEY
```

## Named Arguments

| Argument | Short | Type | Description |
|----------|-------|------|-------------|
| `target` | - | str | **Required** - IP address or domain to lookup |
| `--limit` | `-l` | int | Limit number of results (default: unlimited) |
| `--output` | `-o` | str | Output file path (default: stdout) |
| `--format` | `-f` | str | Output format: txt, json, csv (default: txt) |
| `--sources` | `-s` | list | Data sources to use (default: all non-API sources) |

## Data Sources

### DNS Sources (Fast, No Rate Limits)

| Source | Description | Speed | Notes |
|--------|-------------|-------|-------|
| **dns-ptr** | DNS PTR record lookup | ⚡⚡⚡ | Primary reverse DNS |
| **dns-bruteforce** | Common subdomain enumeration | ⚡⚡ | Tests common subdomains |
| **host** | System host command | ⚡⚡ | Native DNS lookup |

### Web Scraping Sources (Free, Rate Limited)

| Source | Description | Speed | Coverage |
|--------|-------------|-------|----------|
| **viewdns** | ViewDNS.info API | ⚡ | Good initial results |
| **bing** | Bing search results | ⚡ | May find hidden domains |
| **duckduckgo** | DuckDuckGo search | ⚡ | Privacy-focused search |
| **netcraft** | Netcraft site report | ⚡ | Historical data |
| **yougetsignal** | YouGetSignal lookup | ⚡ | Clean results |
| **iphostinfo** | IPHostInfo domains | ⚡ | Web hosting data |
| **domainbigdata** | DomainBigData lookup | ⚡ | Comprehensive |
| **myip** | MyIP.ms reverse IP | ⚡ | Detailed reports |

### Certificate Transparency Sources

| Source | Description | Speed | Notes |
|--------|-------------|-------|-------|
| **crtsh** | Certificate Transparency logs | ⚡⚡ | Finds all SSL certificates |

### API Sources (Requires API Key)

| Source | Description | Speed | Coverage | API Key |
|--------|-------------|-------|----------|---------|
| **censys** | Censys API | ⚡⚡⚡ | Very High | `--censys-api-id` + `--censys-api-secret` |
| **shodan** | Shodan API | ⚡⚡⚡ | Very High | `--shodan-api-key` |
| **zoomeye** | ZoomEye API | ⚡⚡ | High | `--zoomeye-api-key` |
| **virustotal** | VirusTotal API | ⚡ | Medium | `--virustotal-api-key` |

## API Key Setup

### Censys
```bash
# Get API ID and Secret from: https://search.censys.io/account
export CENSYS_API_ID="your_api_id"
export CENSYS_API_SECRET="your_api_secret"
```

### Shodan
```bash
# Get API Key from: https://developer.shodan.io/api
export SHODAN_API_KEY="your_api_key"
```

### ZoomEye
```bash
# Get API Key from: https://www.zoomeye.hk/user
export ZOOMEYE_API_KEY="your_api_key"
```

### VirusTotal
```bash
# Get API Key from: https://www.virustotal.com/myapikey
export VIRUSTOTAL_API_KEY="your_api_key"
```

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
# Find all domains on suspicious IP
python main.py 192.0.2.1 --limit 200 --output suspicious.txt

# Use API sources for comprehensive results
python main.py 203.0.113.1 --sources censys shodan zoomeye --output scan.json

# Certificate transparency search
python main.py example.com --sources crtsh dns-ptr --output certificates.txt
```

### SEO Analysis

```bash
# Check competitor hosting
python main.py 203.0.113.1 --sources viewdns bing netcraft --format json --output competitor.json

# Find all subdomains
python main.py example.com --sources dns-ptr dns-bruteforce crtsh
```

### Comprehensive Search

```bash
# Use all free sources (default)
python main.py 1.1.1.1 --output all-domains.txt

# Use all sources including APIs
python main.py 1.1.1.1 --sources dns-ptr dns-bruteforce viewdns bing duckduckgo netcraft yougetsignal iphostinfo domainbigdata myip crtsh censys shodan zoomeye virustotal
```

## How It Works

1. **Input**: IP address or domain name
2. **Domain Resolution**: If domain is provided, resolves to IP using DNS
3. **Source Selection**: Runs selected sources concurrently
4. **Result Collection**: Aggregates domains from all sources
5. **Filtering**: Removes duplicates and common false positives (CDNs, cloud providers)
6. **Output**: Formats and saves results

## Smart Filtering

Automatically filters out common false positives:
- Cloudflare domains (`.cloudflare.com`, `.cloudflare.net`)
- Akamai domains (`.akamai.net`, `.akamaized.net`)
- Fastly domains (`.fastly.net`)
- AWS domains (`.amazonaws.com`)
- Google domains (`.googleusercontent.com`)

## Requirements

- Python 3.7+
- aiohttp
- dnspython

## Tips

- **Start fast**: Use DNS sources (`dns-ptr`, `host`) for quick results
- **Deep search**: Add web scraping sources (`viewdns`, `bing`, `crtsh`)
- **Comprehensive**: Use API sources (`censys`, `shodan`) with API keys
- **Rate limiting**: Web scraping sources have built-in delays
- **Combine sources**: Use multiple sources for best coverage

## Notes

- **Rate limiting**: Web sources include delays to avoid blocking
- **Accuracy**: Results vary by source and IP; combine multiple sources
- **Privacy**: Uses public data sources only
- **Legal**: Use responsibly and only on IPs/domains you have permission to investigate
- **False positives**: Smart filtering removes common false positives

## Troubleshooting

### DNS Resolution Issues
```bash
# Test DNS resolution
python main.py google.com
# If fails, check your DNS server
```

### API Key Issues
```bash
# Verify API keys are set
echo $SHODAN_API_KEY
echo $CENSYS_API_ID
```

### Rate Limiting
```bash
# Use fewer sources to avoid rate limits
python main.py 8.8.8.8 --sources dns-ptr viewdns
```

## License

MIT

## Contributing

Pull requests welcome! Add more data sources or improve existing ones.

## Credits

Built with Python, aiohttp, dnspython, and various public APIs.
