# theHarvester OSINT Actor

Wraps [laramies/theHarvester](https://github.com/laramies/theHarvester) — the OSINT tool used by penetration testers and red teams to gather **emails, subdomains, IPs, URLs, and ASNs** from public sources.

This actor exposes the **full CLI surface** of theHarvester (16 flags, 54 data sources) as a structured Apify input. Results are pushed as individual dataset records (one per host/email/IP/etc) plus a summary row — perfect for tables, CSV export, or downstream pipelines.

## Quick start

```json
{
  "domain": "example.com",
  "sources": ["crtsh", "hackertarget", "rapiddns", "certspotter"]
}
```

These four sources are **free and require no API key**. For a basic domain, expect 100-1000 subdomains in 30-60 seconds.

## Full power (with API keys)

```json
{
  "domain": "example.com",
  "sources": ["all"],
  "dnsBrute": true,
  "takeOver": true,
  "shodan": true,
  "shodanApiKey": "YOUR_KEY",
  "securitytrailsApiKey": "YOUR_KEY",
  "virustotalApiKey": "YOUR_KEY",
  "hunterApiKey": "YOUR_KEY"
}
```

## What you get

The dataset receives one record per finding, with `recordType` discriminator:

| recordType | Fields | When emitted |
|---|---|---|
| `host` | `host`, `ip`, `domain` | One per discovered subdomain |
| `email` | `email`, `domain` | One per discovered email |
| `ip` | `ip`, `domain` | One per discovered IP |
| `url` | `url`, `domain` | One per discovered "interesting URL" |
| `asn` | `asn`, `domain` | One per discovered ASN |
| `shodan` | `shodan` (object) | One per host enriched by Shodan |
| `person` | `person`, `domain` | One per discovered person/name |
| `summary` | `counts`, `sources`, `success`, `cmd` | One per run — always last |

## 54 supported data sources

**Free (no API key):**
crtsh, hackertarget, rapiddns, certspotter, otx, urlscan, threatcrowd, dnsdumpster, brave, duckduckgo, baidu, yahoo, mojeek, commoncrawl, waybackarchive, robtex, sitedossier, anubis, subdomaincenter, hudsonrock, thc

**Paid / API key required:**
shodan, censys, virustotal, securityTrails, hunter, hunterhow, intelx, fullhunt, netlas, leakix, leaklookup, zoomeye, criminalip, dehashed, fofa, github-code, gitlab, bitbucket, bevigil, builtwith, chaos, projectdiscovery, onyphe, pentesttools, rocketreach, securityscorecard, subdomainfinderc99, tomba, venacus, whoisxml, windvane, dymo, haveibeenpwned, bufferoverun, shodanInternetDB

## Mapped CLI flags

Every theHarvester CLI flag is exposed:

| CLI flag | Actor input | Notes |
|---|---|---|
| `-d` | `domain` | Required |
| `-b` | `sources` | Comma-separated or array |
| `-l` | `limit` | Per-source result cap |
| `-S` | `start` | Pagination offset |
| `-n` | `dnsLookup` | Resolve discovered hosts |
| `-c` | `dnsBrute` | Brute-force subdomains |
| `-r` | `dnsResolve` | Custom resolver list |
| `-e` | `dnsServer` | DNS server IP |
| `-s` | `shodan` | Enrich via Shodan |
| `-t` | `takeOver` | Subdomain takeover check |
| `--screenshot` | `screenshot` | Capture subdomain screenshots |
| `-a` | `apiScan` | API endpoint scan |
| `-w` | `wordlist` | Wordlist path (cloud-limited) |
| `-p` | `useProxies` | Use proxies.yaml |
| `-q` | `quiet` | Suppress key warnings |
| `-f` | (internal) | Output is parsed and pushed automatically |

## Notes for Apify cloud

- **Screenshots** write to `/tmp/screenshots` inside the container. They are not yet auto-uploaded to the key-value store — that's planned.
- **Wordlist** must reference a file that exists inside the Docker image. Custom wordlists from the input field do not transfer.
- **Proxies** require a `proxies.yaml` baked into the image. Skip `useProxies` unless you've forked this actor with a custom image.
- **API keys** are isSecret — they are stored encrypted and not logged.

## FAQ

### Do I need API keys?
Not for basic recon — the 4 free sources (crtsh, hackertarget, rapiddns, certspotter) work without any keys and return 100-1000 subdomains for most domains. API keys unlock deeper sources like Shodan, Censys, VirusTotal, SecurityTrails, and Hunter.

### Which sources should I pick first?
For pure subdomain discovery: `crtsh, certspotter, hackertarget, rapiddns, otx, dnsdumpster, anubis, subdomaincenter` — all free, all complement each other. For emails: add `hunter` (paid) or `intelx` (paid).

### Why are some sources returning 0 results?
A few sources require a working API key (you'll see "key not set" warnings in logs). Others rate-limit per-IP — re-running 10 minutes later usually works. CommonCrawl + WaybackArchive can be slow on large domains; bump `limit` if needed.

### Can I combine this with nmap for full recon?
Yes — that's the canonical workflow. theHarvester finds subdomains → feed each into nmap → nmap returns open ports + services per host. Stitch them into a single recon report via Apify's webhook output.

### How does this differ from running `theHarvester` locally?
Same binary, but you skip the install pain (Python deps, system requirements, proxy setup), and outputs are pre-parsed into structured records ready for CSV/Google Sheets/Notion. You also get Apify Residential Proxies built-in.

## Pairs nicely with

Bundle for full attack-surface mapping:

- **[nmap](https://apify.com/anshumanatrey/nmap-scanner)** — Port-scan every subdomain theHarvester discovers
- **[NetIntel](https://apify.com/anshumanatrey/netintel)** — Enrich each discovered IP with WHOIS, GeoIP, SSL, reputation data
- **[Bug Bounty Finder](https://apify.com/anshumanatrey/bug-bounty-finder)** — Check whether the target has a public bounty program before reporting
- **[Holehe Email OSINT](https://apify.com/anshumanatrey/holehe-email-osint)** — Take the discovered emails and find which sites they're registered on
- **[Social Analyzer](https://apify.com/anshumanatrey/social-analyzer)** — Investigate the people behind the discovered emails
- **[Zomato Restaurant Scraper](https://apify.com/anshumanatrey/zomato-restaurant-scraper)** — Restaurant lead lists (separate B2B use case)

## Credits

Built on top of [theHarvester](https://github.com/laramies/theHarvester) by Christian Martorella (Edge Security). MIT/GPL licensed per upstream.
