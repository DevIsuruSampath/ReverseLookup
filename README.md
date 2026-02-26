# Reverse IP Lookup Tool - Smart Version

**Smart reverse IP lookup** with advanced filtering, Kali Linux tools (amass, dnsrecon, sublist3r), Certificate Transparency, and subdomain enumeration. No external APIs required.

## Features

- 🎯 **Smart filtering** - Removes WHOIS noise, abuse domains, CDN infrastructure
- 🛡️ **Kali Linux tools** - Amass, DNSrecon, Sublist3r integration
- 📊 **10+ sources** - Certificate Transparency, DNS records, bruteforce
- ⚡ **Parallel processing** - 30 threads for fast subdomain enumeration
- 🧩 **Domain support** - Auto-resolves domains to IPs
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- 📦 **Zero dependencies** - Only dnspython required
- 📱 **Cross-platform** - Linux, Kali, Termux, macOS, Windows

## Installation

### Kali Linux (Recommended)

```bash
# Clone repo
git clone https://github.com/DevIsuruSampath/ReverseLookup.git
cd ReverseLookup

# Install Python dependencies
pip install -r requirements.txt

# Install Kali tools (for best results)
sudo apt update
sudo apt install -y amass dnsrecon sublist3r
```

### Standard Linux

```bash
pip install dnspython
# Tool works without Kali tools
```

### Termux (Android)

```bash
pkg install python python-pip
pip install dnspython
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

### Kali Linux Tools

| Tool | Description | Install Command |
|------|-------------|-----------------|
| **Amass** | Asset discovery (passive, 45s timeout) | `apt install amass` |

## Smart Filtering

### Removed Domains (Noise)

The tool automatically filters out:

- **Registry domains**: arin.net, rdap.arin.net, ripe.net, apnic.net, etc.
- **Abuse domains**: dis.abuse, dis.incapsula.noc, knack.black, etc.
- **AWS infrastructure**: amazonaws.com, compute.amazonaws.com, ec2.internal, waf.amazonaws.com, support.amazonaws.com, www.amazonaws.com, cloudfront.net, s3.amazonaws.com, route53.amazonaws.com
- **GCP infrastructure**: googleapis.com, googleusercontent.com, cloudfunctions.net, appspot.com
- **Azure infrastructure**: cloudapp.azure.com, azurewebsites.net, windowsazure.com, azure.net
- **CDN infrastructure**: cloudflare.net, fastly.net, akamai.net, cdn77.net, cdn.jsdelivr.net
- **IP-like domains**: Numeric patterns (e.g., 192-168-1-1)
- **Amass noise**: ASN, netblock, managed_by, rirorganization lines

### Prioritized Domains

The tool prioritizes:
- Real domains on the target IP
- Related subdomains
- Service domains
- Infrastructure domains

## Data Sources (All run automatically)

### Python Sources (Always Available)
- **DNS-PTR** - Primary reverse DNS
- **crt.sh** - Certificate Transparency logs
- **DNS-MX** - Mail server domains
- **DNS-NS** - Nameserver domains
- **DNS-SRV** - Service-related domains
- **Advanced-Brute** - 90+ prioritized subdomains (parallel)

### Kali Linux Tools (Optional)
- **Amass** - Comprehensive asset discovery
- **DNSrecon** - DNS reconnaissance
- **Sublist3r** - Subdomain enumeration

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

### Kali Linux - Full Scan
```bash
# Install Kali tools first
sudo apt install -y amass dnsrecon sublist3r

# Run full scan
python main.py 1.1.1.1 --output full-scan.txt
```

### Domain Lookup
```bash
python main.py viber.com --output viber-domains.txt
```

### Different Targets
```bash
# DNS servers
python main.py 8.8.8.8
python main.py 1.1.1.1

# Popular domains
python main.py google.com
python main.py facebook.com
python main.py dialog.lk
```

## How It Works

1. **Input**: IP address or domain name
2. **Resolution**: If domain, resolves to IP
3. **DNS Queries**: PTR, MX, NS, SRV lookups
4. **Certificate Transparency**: Queries crt.sh and Censys CT for SSL certificates
5. **Cloud Domain Extraction**: Extracts parent domains from AWS/GCP/Azure PTR records
6. **Subdomain Bruteforce**: Tests 120+ prioritized subdomains in parallel (30 threads)
6. **Kali Tools**: Runs Amass, DNSrecon, Sublist3r if available
7. **Smart Filtering**: Removes noise and irrelevant domains
8. **Aggregation**: Collects all unique, relevant domains
9. **Output**: Formats and saves results

## Subdomains Tested (90+ Prioritized)

### Priority 1: Most Common (10)
www, mail, api, m, mobile, app, dev, test, admin, portal, panel

### Priority 2: Infrastructure (20)
cdn, static, assets, img, images, video, media, upload, download, files, docs, blog, shop, store, support, help, community, forum, wiki

### Priority 3: Auth (10)
auth, login, signin, signup, register, account, oauth, sso, identity, password, token

### Priority 4: Mail (10)
smtp, pop, imap, exchange, webmail, email, mail1, mail2, mx, ns1, ns2

### Priority 5: Tech (15)
db, database, cache, redis, mongo, elastic, search, kibana, grafana, prometheus, log, metrics, monitor

### Priority 6: DevOps (15)
jenkins, gitlab, github, git, svn, nexus, artifactory, docker, k8s, kubernetes, helm, argo, consul, vault, nomad

### Priority 7: Security (10)
ssl, secure, vpn, firewall, gateway, proxy, lb, loadbalancer, waf, ids, ips

### Priority 8: Regional (10)
us, eu, asia, na, sa, emea, apac, us-east, us-west, eu-west, eu-central, ap-south

### Priority 9: Versioned (10)
v1, v2, v3, v4, api-v1, api-v2, api-v3, web-v1, web-v2, mobile-v1

### Priority 10: Platform (10)
ios, android, web, client, server, backend, frontend, api-v1, api-v2, app-v1, app-v2

### Priority 11: Business (15)
hr, crm, erp, billing, payment, checkout, cart, order, calendar, drive, storage, backup, archive

## Performance

- **DNS lookups**: Fast (0.3-1 seconds)
- **Certificate Transparency**: Fast (5-15 seconds, crt.sh only)
- **Fast Brute Force**: Very fast (5-15 seconds for 60 subdomains)
- **Amass**: Medium (30-45 seconds, passive mode)
- **Total scan**: 20-60 seconds depending on target

## Advantages

✅ **Smart filtering** - Removes WHOIS noise, abuse domains, cloud infrastructure
✅ **Kali optimized** - Uses Amass passive mode
✅ **No APIs** - Uses public CT logs and direct queries
✅ **No rate limits** - Parallel processing
✅ **Fast** - Complete scan in 20-60 seconds
✅ **Privacy** - No data shared with third parties
✅ **Cross-platform** - Works everywhere Python runs
✅ **Optional Kali tools** - Works without them

## Requirements

### Minimum
- Python 3.7+
- dnspython

### Recommended (Kali Linux)
- amass
- dnsrecon
- sublist3r

## Tips

- **Kali users**: Install Amass for best results (most comprehensive)
- **Quick scan**: DNS-PTR + crt.sh + Advanced-Brute
- **Deep scan**: Add Amass + DNSrecon + Sublist3r
- **Smart filtering**: Automatically removes noise domains
- **Parallel processing**: Bruteforce uses 30 threads for speed

## Certificate Transparency

For detailed information about Certificate Transparency sources, see [CT_SOURCES.md](CT_SOURCES.md).

## Troubleshooting

### Still Getting Noise Domains

```bash
# The smart filter should remove most noise
# If you still see noise, check the domain list manually
```

### Amass Not Finding Anything

```bash
# Amass uses passive mode (no active scanning)
# Some domains don't have many public certificates
# Try other sources: DNSrecon, Sublist3r
```

### DNSrecon Output File Not Found

```bash
# Make sure /tmp directory is writable
# Or try running with sudo
sudo python main.py 1.1.1.1
```

## License

MIT

## Contributing

Pull requests welcome! Add more tools or improve smart filtering.

## Credits

Built with Python, dnspython, and Kali Linux tools (Amass, DNSrecon, Sublist3r).
