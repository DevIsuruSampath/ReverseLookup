# Termux Compatibility Notes

## Running on Termux (Android)

This tool is fully compatible with Termux on Android. It automatically handles the lack of `/etc/resolv.conf` file and uses public DNS servers.

### Installation on Termux

```bash
# Update packages
pkg update && pkg upgrade

# Install Python and pip
pkg install python python-pip

# Install dnspython
pip install dnspython

# Clone or download the tool
cd ~
git clone https://github.com/DevIsuruSampath/ReverseLookup.git
cd ReverseLookup

# Run the tool
python main.py google.com --output results.txt
```

### How It Works on Termux

1. **DNS Resolver Detection**: Automatically detects if `/etc/resolv.conf` is missing
2. **Fallback DNS**: Uses public DNS servers when resolv.conf is not available:
   - 8.8.8.8 (Google DNS)
   - 8.8.4.4 (Google DNS)
   - 1.1.1.1 (Cloudflare DNS)
   - 1.0.0.1 (Cloudflare DNS)

### Testing on Termux

```bash
# Test DNS resolution
python main.py 8.8.8.8

# Test domain lookup
python main.py viber.com --output results.txt

# Test with JSON output
python main.py google.com --format json --output domains.json
```

### Known Issues & Solutions

#### Issue: dnspython import error
```bash
# Solution: Reinstall dnspython
pip uninstall dnspython
pip install dnspython
```

#### Issue: ModuleNotFoundError: No module named 'dns'
```bash
# Solution: Install dnspython
pip install dnspython
```

#### Issue: No resolver configuration
```bash
# This is now handled automatically by the tool
# If you still see this error, try:
rm -rf /data/data/com.termux/files/usr/lib/python3.*/site-packages/dns
pip install --force-reinstall dnspython
```

### Performance on Termux

The tool runs efficiently on Android devices. Performance varies by:

- **Network speed**: DNS queries require internet
- **CPU speed**: Subdomain bruteforce can be CPU intensive
- **DNS server response time**: Public DNS servers vary

### Battery Optimization

For battery-conscious use:

```bash
# Skip bruteforce (edit sources list in code)
# Use only DNS-PTR and Host commands
```

### Root vs Non-Root

The tool works **without root** on Termux. No special permissions required.

### Alternatives to Termux

If you prefer other Android terminals:

- **UserLAnd**: Full Linux environment
- **AndroLinux**: Lightweight Linux
- **Proot-Distro**: Various Linux distributions

All should work with the tool as long as Python 3.7+ is available.
