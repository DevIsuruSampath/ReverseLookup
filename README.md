# Reverse IP Lookup Tool - Enhanced Linux/Kali Version

**Enhanced reverse IP lookup** using DNS queries, Linux tools, Kali Linux tools, and Python libraries. No external APIs or data sources required.

## Features

- 🔒 **Multiple methods** - DNS, WHOIS, and Linux reconnaissance tools
- 🛡️ **Kali Linux optimized** - Uses dnsrecon, dnsenum, fierce, amass, nmap
- ⚡ **Fast & Private** - No external requests to third parties
- 🎯 **12+ sources** - PTR, WHOIS, DNS records, and reconnaissance tools
- 🧩 **Domain support** - Auto-resolves domains to IPs
- 💾 **Flexible output** - TXT, JSON, or CSV formats
- 📦 **Zero dependencies** - Only dnspython required
- 📱 **Cross-platform** - Linux, Kali, Termux, macOS, Windows

## Installation

### Standard Linux / Kali Linux

```bash
# Clone or navigate to directory
cd ReverseLookup

# Install Python dependencies
pip install -r requirements.txt

# Optional: Install Kali Linux tools (Kali only or similar distros)
sudo apt update
sudo apt install -y dnsrecon dnsenum fierce amass nmap whois
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

### Kali Linux Tools (Optional)

These tools are automatically used if available:

| Tool | Description | Install Command |
|------|-------------|-----------------|
| **dnsrecon** | DNS reconnaissance | `apt install dnsrecon` |
| **dnsenum** | DNS enumeration | `apt install dnsenum` |
| **fierce** | DNS scanner | `apt install fierce` |
| **amass** | Asset discovery | `apt install amass` |
| **nmap** | Network mapper | `apt install nmap` |
| **whois** | WHOIS client | `apt install whois` |
| **dig** | DNS lookup | `apt install dnsutils` |

## Data Sources (All run automatically)

### DNS Sources (Always Available)
- **DNS-PTR** - DNS PTR record lookup
- **DNS-MX** - DNS MX records (mail servers)
- **DNS-NS** - DNS NS records (name servers)
- **DNS-TXT** - DNS TXT records
- **DNS-SRV** - DNS SRV records (services)

### Linux Tools (Optional)
- **WHOIS** - WHOIS lookup for domain info
- **DIG-AXFR** - DNS Zone Transfer (if allowed)
- **Nmap** - Service discovery

### Kali Linux Tools (Optional)
- **DNSrecon** - DNS reconnaissance tool
- **DNSenum** - DNS enumeration tool
- **Fierce** - DNS scanner
- **Amass** - Asset discovery tool

## Output Formats

### TXT (default)
```
google.com
mail.google.com
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

### Quick Lookup
```bash
python main.py 8.8.8.8
```

### Kali Linux - Full Scan
```bash
# Install all Kali tools first
sudo apt install dnsrecon dnsenum fierce amass nmap whois

# Run full scan
python main.py 1.1.1.1 --output full-scan.txt
```

### Domain Lookup
```bash
python main.py viber.com --output viber-domains.txt
```

## How It Works

1. **Input**: IP address or domain name
2. **Resolution**: If domain, resolves to IP
3. **DNS Queries**: Runs DNS PTR, MX, NS, TXT, SRV lookups
4. **WHOIS**: Queries WHOIS for domain information
5. **Kali Tools**: Uses dnsrecon, dnsenum, fierce, amass if available
6. **Network Scanning**: Uses Nmap for HTTP/HTTPS service discovery
7. **Aggregation**: Collects all unique domains
8. **Output**: Formats and saves results

## Advantages

✅ **Multiple methods** - DNS + WHOIS + Reconnaissance
✅ **Kali optimized** - Uses specialized Kali Linux tools
✅ **No APIs** - No external service dependencies
✅ **No rate limits** - Direct queries only
✅ **Privacy** - No data shared with third parties
✅ **Fast** - Concurrent lookups
✅ **Flexible** - Works with or without Kali tools
✅ **Cross-platform** - Linux, Kali, Termux, macOS, Windows

## Requirements

### Minimum
- Python 3.7+
- dnspython

### Recommended (Kali Linux)
- dnsrecon
- dnsenum
- fierce
- amass
- nmap
- whois
- dnsutils (for dig)

## Tips

- **Kali users**: Install all optional tools for best results
- **Standard Linux**: Tool works with just DNS and WHOIS
- **Quick scan**: DNS sources are faster than reconnaissance tools
- **Deep scan**: Kali tools (amass, dnsrecon) find more subdomains
- **Nmap**: Finds domains from HTTP headers and SSL certificates

## Troubleshooting

### Tool Not Found Errors
```bash
# These are normal if tools aren't installed
# Tool will still work with DNS and WHOIS
```

### DNS Resolution Issues
```bash
# Test DNS resolution
python main.py google.com
```

### Amass Timeout
```bash
# Amass can take time, be patient
# Or install timeout wrapper
```

## License

MIT

## Contributing

Pull requests welcome! Add more tools or improve existing ones.

## Credits

Built with Python, dnspython, and various Linux/Kali tools.
