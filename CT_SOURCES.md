# Certificate Transparency Sources

## Multiple Certificate Transparency Sources

This tool uses **2 different Certificate Transparency logs** for maximum domain discovery:

### 1. crt.sh
- **URL**: https://crt.sh
- **Coverage**: Most comprehensive CT log aggregator
- **Search Method**: Subdomain search with `%.25252` pattern
- **Timeout**: 30 seconds
- **Best For**: Finding all historical certificates

### 2. Censys CT
- **URL**: https://censys.io
- **Coverage**: Additional certificates not in crt.sh
- **Search Method**: DNS name certificate search
- **API**: `/api/v2/certificates?q=dns.names:{domain}`
- **Timeout**: 30 seconds
- **Best For**: Finding additional certificates

## How Certificate Transparency Works

1. **Certificate Issuance**: When an SSL certificate is issued, it's logged to CT
2. **Public Logs**: All CT logs are publicly accessible
3. **Domain Names**: Each certificate contains domain names (CN, SAN)
4. **Historical Data**: Includes expired and revoked certificates
5. **Searchable**: You can query CT logs by domain

## Subdomain Discovery with CT

Certificate Transparency is excellent for finding subdomains because:

- **Wildcard Certificates**: `*.example.com` reveals the domain
- **Multiple Names**: Single cert can have 100+ domains in SAN
- **Historical**: Old certificates reveal forgotten subdomains
- **Internal Domains**: Sometimes leaks internal subdomains

## Smart Cloud Domain Handling

For AWS/GCP/Azure IPs, PTR returns cloud infrastructure domains:

### AWS Example
```
PTR: ec2-23-232-242-252.compute-1.amazonaws.com
→ Extract: amazonaws.com
→ Search CT for: *.amazonaws.com
```

### GCP Example
```
PTR: 34.96.100.100.compute.googleapis.com
→ Extract: googleapis.com
→ Search CT for: *.googleapis.com
```

### Azure Example
```
PTR: vm-name.cloudapp.azure.com
→ Extract: azure.com
→ Search CT for: *.azure.com
```

## CT Search Strategy

The tool searches Certificate Transparency in this order:

1. **PTR Domain Direct**: Search for the exact PTR domain
2. **Extracted Parent Domain**: If PTR is cloud infra, extract parent and search
3. **Pattern Matching**: Use `%.25252` pattern for wildcard subdomains

## Performance

- **crt.sh**: 5-15 seconds (comprehensive)
- **Censys CT**: 3-10 seconds (additional)
- **Total**: 8-25 seconds for both sources
- **Parallel**: Runs concurrently with other sources

## Limitations

⚠️ **New Domains**: Domains without any SSL certificates won't appear
⚠️ **HTTP-Only**: HTTP-only domains (no SSL) won't appear
⚠️ **Rate Limiting**: CT APIs have rate limits (handled automatically)
