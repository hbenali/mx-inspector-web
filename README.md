# MX Checker

A free, single-page MX (mail exchanger) record checker and generator. Live at [mx.hbenali.ovh](https://mx.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling a public DNS-over-HTTPS API from the browser.

## Features

- **Lookup** a domain's MX records, sorted by priority and labeled primary or backup
- **Host resolution**: each mail host's A/AAAA records are resolved
- **Checks**: null MX (RFC 7505), MX target that is a CNAME or an IP, NXDOMAIN or address-less hosts, private addresses, duplicate priorities, single-MX, implicit-MX fallback to the A record
- **Mail transport security**: reverse DNS (PTR) of each host, DANE TLSA records, MTA-STS and TLS-RPT records
- **Cross-links** to the email audit, SPF, DKIM, DMARC, BIMI, MTA-STS, DANE, DNSSEC, DNS, delegation and CAA tools for the same domain
- **Provider detection** (Google Workspace, Microsoft 365, Proton, Fastmail, Zoho, iCloud, OVHcloud and others)
- **Generator** with provider presets, load-from-lookup, and BIND zone-file output
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

`?domain=example.com` runs a lookup on load.

## Data sources

- [dns.google](https://developers.google.com/speed/public-dns/docs/doh): DNS-over-HTTPS for MX, A and AAAA lookups

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
