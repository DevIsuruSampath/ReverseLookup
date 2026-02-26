# Reverse IP Lookup Tool - Advanced Python Version

**Advanced reverse IP lookup** using Python techniques, DNS queries, Certificate Transparency, HTTP scraping, SSL/TLS parsing, and more. No external APIs or data sources required.

## Features

- 🚀 **Advanced Python techniques** - Certificate Transparency, HTTP headers, SSL parsing
- 📊 **12+ sources** - Multiple intelligent discovery methods
- 🔍 **Smart discovery** - CNAME chains, subdomain enumeration (150+)
- 🛡️ **Cross-platform** - Works on Linux, Kali, Termux, macOS, Windows
- ⚡ **Parallel processing** - Concurrent DNS and HTTP queries
- 🧩 **Domain support** - Auto-resolves domains to IPs
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- 📦 **Minimal dependencies** - Only dnspython required

## Installation

```bash
# Clone or navigate to directory
cd ReverseLookup

# Install Python dependencies
pip install -r requirements.txt

# Optional: Install WHOIS (Linux/Kali)
sudo apt install -y whois

# Optional: Install DNSrecon (Kali Linux)
sudo apt install -y dnsrecon
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

## Advanced Python Techniques

| Technique | Description | What it finds |
|-----------|-------------|---------------|
| **crt.sh** | Certificate Transparency logs | All SSL certificates ever issued |
| **HTTP-Header** | HTTP header scraping | Domains in headers (Server, X-Powered-By, etc.) |
| **SSL-Cert** | SSL/TLS certificate parsing | Domains from certificates (CN, SAN) |
| **CNAME-Chain** | CNAME chain traversal | Aliases and redirect domains |
| **Advanced-Brute** | Parallel subdomain enumeration | 150+ common subdomains |
| **DNS-PTR** | DNS PTR record | Primary reverse DNS |
| **DNS-MX** | DNS MX records | Mail server domains |
| **DNS-NS** | DNS NS records | Nameserver domains |
| **DNS-SRV** | DNS SRV records | Service-related domains |
| **WHOIS** | WHOIS lookup | Domain ownership info |
| **DNSrecon** | Kali tool (optional) | DNS reconnaissance |

## Data Sources Explained

### Certificate Transparency (crt.sh)
- Queries public CT logs
- Finds ALL SSL certificates ever issued for a domain
- Includes expired and subdomain certificates
- No rate limiting
- **Very powerful for discovery**

### HTTP Header Scraping
- Sends HTTP requests to common endpoints
- Extracts domains from headers:
  - `Server`
  - `X-Powered-By`
  - `Via`
  - `X-Forwarded-For`
  - `Location` (redirects)

### SSL/TLS Certificate Parsing
- Connects to HTTPS endpoints
- Extracts domains from:
  - Common Name (CN)
  - Subject Alternative Names (SAN)
- Finds virtual host configurations

### CNAME Chain Traversal
- Follows CNAME redirects
- Up to 3 hops deep
- Finds aliased domains

### Advanced Subdomain Brute Force
- 150+ subdomain patterns including:
  - Common (www, mail, api, dev)
  - Infrastructure (cdn, static, cache)
  - Services (blog, shop, portal)
  - Tech stack (db, redis, elastic)
  - DevOps (k8s, docker, jenkins)
  - Regional (us-east, eu-west, ap-south)
  - Versioned (api-v1, v2, v3)
  - Platform (ios, android, mobile)
- **Parallel processing** for speed
- Tests against A, AAAA, CNAME records

## Output Formats

### TXT (default)
```
google.com
mail.google.com
analytics.google.com
...
Total: 50 domains
```

### JSON
```json
{
  "domains": ["google.com", "mail.google.com", ...],
  "total": 50
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

### Quick Lookup
```bash
python main.py 8.8.8.8
```

### Advanced Scan (all Python techniques)
```bash
python main.py viber.com --output viber-domains.txt
```

### Domain Lookup
```bash
python main.py google.com --format json --output google.json
```

### With Kali Tools (if available)
```bash
# Install Kali tools
sudo apt install -y whois dnsrecon

# Run with all sources
python main.py 1.1.1.1 --output all-domains.txt
```

## How It Works

1. **Input**: IP address or domain name
2. **Resolution**: If domain, resolves to IP
3. **Certificate Transparency**: Queries crt.sh for all certificates
4. **HTTP Scraping**: Tests common endpoints and scrapes headers
5. **SSL Parsing**: Extracts domains from SSL certificates
6. **CNAME Traversal**: Follows CNAME chains
7. **Subdomain Bruteforce**: Parallel testing of 150+ subdomains
8. **DNS Records**: PTR, MX, NS, SRV lookups
9. **WHOIS**: Queries WHOIS for domain info
10. **Aggregation**: Collects all unique domains
11. **Output**: Formats and saves results

## Subdomains Tested (150+)

### Common (20)
www, mail, ftp, admin, api, dev, test, staging, production, app, apps, m, wap, web

### Infrastructure (25)
cdn, static, assets, img, images, video, media, upload, download, files, docs, wiki, help, support, forum, community, blog, shop, store, portal, dashboard, panel, secure, vpn, proxy, gateway, lb, loadbalancer

### Services (15)
pop, imap, smtp, exchange, email, webmail, db, database, mysql, postgres, mongodb, redis, elastic, cache, memcache, varnish

### DevOps (20)
jenkins, gitlab, github, git, nexus, artifactory, sonarqube, grafana, prometheus, kibana, elasticsearch, k8s, kubernetes, docker, registry, helm, argo, consul, vault, nomad, terraform, ansible

### Monitoring (10)
monitor, alert, log, metrics, traces, jaeger, zipkin, tempo, loki, promtail, fluentd

### Regional (20)
us, eu, asia, na, sa, emea, apac, latam, us-east, us-west, eu-west, eu-central, eu-north, eu-south, ap-south, ap-east, ap-north, ap-southeast, sa-east

### Versioned (10)
v1, v2, v3, v4, v5, api-v1, api-v2, api-v3, api-v4, api-v5

### Platform (10)
ios, android, mobile, tablet, desktop, web, browser, app, client, server, backend

### Business (15)
hr, crm, erp, mail, email, calendar, drive, storage, backup, archive, analytics, stats, reports, billing, account, payment

### Security (10)
ssl, secure, auth, oauth, sso, login, signin, signup, register, password, token

### Misc (20)
beta, alpha, preview, demo, sandbox, staging, qa, uat, prod, live, production, internal, external, public, private, admin, manage, console

## Performance

- **DNS lookups**: Fast (0.5-2 seconds)
- **Certificate Transparency**: Medium (5-15 seconds)
- **HTTP Scraping**: Fast (1-3 seconds per endpoint)
- **SSL Parsing**: Fast (1-2 seconds per endpoint)
- **Subdomain Bruteforce**: Medium (10-30 seconds)
- **Total scan**: 20-60 seconds depending on target

## Advantages

✅ **No APIs** - Uses public CT logs and direct queries
✅ **No rate limits** - Parallel processing
✅ **Very comprehensive** - Multiple discovery methods
✅ **Smart** - Filters out false positives (AWS, cloud providers)
✅ **Fast** - Concurrent lookups
✅ **Privacy** - No data shared with third parties
✅ **Cross-platform** - Works everywhere Python runs
✅ **Optional Kali tools** - Works without them

## Requirements

### Minimum
- Python 3.7+
- dnspython

### Optional (for better results)
- whois
- dnsrecon (Kali)

## Tips

- **Best results**: All Python techniques run automatically
- **Deep scan**: Certificate Transparency + SSL Parsing + HTTP Headers
- **Quick scan**: DNS-PTR + DNS-MX + DNS-NS
- **Subdomain discovery**: Advanced-Brute finds 150+ subdomains
- **AWS/Cloud IPs**: Automatically filtered, but check parent domain

## Troubleshooting

### No Domains Found
```
# Some IPs (AWS, GCP) don't expose many domains
# Try the parent domain instead
```

### SSL/TLS Certificate Errors
```
# Normal if no SSL certificate on that port
# Tool will continue to other methods
```

### Timeout Errors
```
# Certificate Transparency can be slow
# HTTP scraping has built-in timeout
# Wait for completion
```

## License

MIT

## Contributing

Pull requests welcome! Add more techniques or improve existing ones.

## Credits

Built with Python, dnspython, and public Certificate Transparency logs.
