"""
theHarvester OSINT Actor - wraps the laramies/theHarvester CLI with full feature parity.

Output strategy:
- Push 1 "summary" record with aggregate counts + the full structured payload (raw)
- Push individual records for each host, email, IP, URL, ASN - billable per record + nicely paged in Apify Console
"""
import asyncio
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml
from apify import Actor


# upstream api-keys.yaml structure: top-level "apikeys:" mapping, each service has {key,...}
# Source: https://github.com/laramies/theHarvester/blob/master/theHarvester/data/api-keys.yaml
API_KEY_FIELDS = {
    # service_in_yaml: list of (wrapper_input_key, yaml_subkey)
    'bevigil':            [('bevigilApiKey', 'key')],
    'bitbucket':          [('bitbucketApiKey', 'key')],
    'brave':              [('braveApiKey', 'key')],
    'bufferoverun':       [('bufferoverunApiKey', 'key')],
    'builtwith':          [('builtwithApiKey', 'key')],
    'censys':             [('censysApiId', 'id'), ('censysApiSecret', 'secret')],
    'chaos':              [('chaosApiKey', 'key')],
    'criminalip':         [('criminalipApiKey', 'key')],
    'dehashed':           [('dehashedApiKey', 'key')],
    'dnsdumpster':        [('dnsdumpsterApiKey', 'key')],
    'dymo':               [('dymoApiKey', 'key')],
    'fofa':               [('fofaKey', 'key'), ('fofaEmail', 'email')],
    'fullhunt':           [('fullhuntApiKey', 'key')],
    'github':             [('githubToken', 'key')],
    'hackertarget':       [('hackertargetApiKey', 'key')],
    'haveibeenpwned':     [('hibpApiKey', 'key')],
    'hunter':             [('hunterApiKey', 'key')],
    'hunterhow':          [('hunterhowApiKey', 'key')],
    'intelx':             [('intelxApiKey', 'key')],
    'leakix':             [('leakixApiKey', 'key')],
    'leaklookup':         [('leaklookupApiKey', 'key')],
    'mojeek':             [('mojeekApiKey', 'key')],
    'netlas':             [('netlasApiKey', 'key')],
    'onyphe':             [('onypheApiKey', 'key')],
    'pentestTools':       [('pentesttoolsApiKey', 'key')],
    'projectDiscovery':   [('projectdiscoveryApiKey', 'key')],
    'rocketreach':        [('rocketreachApiKey', 'key')],
    'securityscorecard':  [('securityscorecardApiKey', 'key')],
    'securityTrails':     [('securitytrailsApiKey', 'key')],
    'shodan':             [('shodanApiKey', 'key')],
    'subdomainfinderc99': [('subdomainfinderc99ApiKey', 'key')],
    'tomba':              [('tombaKey', 'key'), ('tombaSecret', 'secret')],
    'venacus':            [('venacusApiKey', 'key')],
    'virustotal':         [('virustotalApiKey', 'key')],
    'whoisxml':           [('whoisxmlApiKey', 'key')],
    'windvane':           [('windvaneApiKey', 'key')],
    'zoomeye':            [('zoomeyeApiKey', 'key')],
}

CONFIG_DIR = Path(os.path.expanduser('~/.theHarvester'))
OUTPUT_PREFIX = '/tmp/theharvester_output'
SCREENSHOT_DIR = '/tmp/screenshots'


def clean_domain(raw: str) -> str:
    """Normalize user-pasted input into a bare domain theHarvester can use.

    Turns 'https://www.itm.edu/path' into 'itm.edu', pulls the domain out of an
    email, and strips ports - so a pasted URL still returns full results instead
    of a near-empty run. Real subdomains (sub.example.com) are preserved.
    """
    if not raw:
        return raw
    s = str(raw).strip().lower()
    if '@' in s:                                    # email -> domain part
        s = s.split('@', 1)[1]
    s = re.sub(r'^[a-z][a-z0-9+.\-]*://', '', s)    # strip scheme (https:// etc.)
    s = re.split(r'[/\s?#]', s, 1)[0]               # strip path / query / spaces
    s = s.split(':', 1)[0]                          # strip port
    if s.startswith('www.'):
        s = s[4:]
    return s.rstrip('.')


def _is_ip(s: str) -> bool:
    return bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', s))


def looks_like_domain(s: str) -> bool:
    """True if s is a usable domain or IP. Rejects spaces, junk, and bare words."""
    if not s:
        return False
    if _is_ip(s):
        return True
    return bool(re.fullmatch(
        r'(?=.{1,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}', s))


def build_api_keys_file(input_data: dict) -> int:
    """Write ~/.theHarvester/api-keys.yaml from provided API keys. Returns count of services configured."""
    api_keys = {}

    for service, fields in API_KEY_FIELDS.items():
        service_keys = {}
        for input_key, yaml_subkey in fields:
            value = input_data.get(input_key)
            if value:
                service_keys[yaml_subkey] = value
        if service_keys:
            api_keys[service] = service_keys

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    api_keys_path = CONFIG_DIR / 'api-keys.yaml'

    if api_keys:
        with open(api_keys_path, 'w') as f:
            yaml.dump({'apikeys': api_keys}, f, default_flow_style=False)
        Actor.log.info(f'Wrote api-keys.yaml with {len(api_keys)} services configured: {sorted(api_keys.keys())}')
    else:
        # write an empty file so theHarvester doesn't warn - quieter logs
        if not api_keys_path.exists():
            with open(api_keys_path, 'w') as f:
                yaml.dump({'apikeys': {}}, f, default_flow_style=False)
        Actor.log.info('No API keys provided - running with free sources only')

    return len(api_keys)


def build_command(input_data: dict) -> list:
    """Build the theHarvester argv from the actor input."""
    domain = input_data['domain']
    cmd = ['theHarvester', '-d', domain]

    sources = input_data.get('sources') or ['crtsh', 'hackertarget', 'rapiddns', 'certspotter']
    if isinstance(sources, list):
        sources_str = ','.join(sources)
    else:
        sources_str = sources
    cmd.extend(['-b', sources_str])

    if input_data.get('limit'):
        cmd.extend(['-l', str(input_data['limit'])])

    if input_data.get('start'):
        cmd.extend(['-S', str(input_data['start'])])

    if input_data.get('dnsResolve'):
        cmd.extend(['-r', input_data['dnsResolve']])

    if input_data.get('dnsLookup'):
        cmd.append('-n')

    if input_data.get('dnsBrute'):
        cmd.append('-c')

    if input_data.get('dnsServer'):
        cmd.extend(['-e', input_data['dnsServer']])

    if input_data.get('shodan'):
        cmd.append('-s')

    if input_data.get('takeOver'):
        cmd.append('-t')

    if input_data.get('screenshot'):
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
        cmd.extend(['--screenshot', SCREENSHOT_DIR])

    if input_data.get('apiScan'):
        cmd.append('-a')

    if input_data.get('wordlist'):
        cmd.extend(['-w', input_data['wordlist']])

    if input_data.get('useProxies'):
        cmd.append('-p')

    if input_data.get('quiet'):
        cmd.append('-q')

    cmd.extend(['-f', OUTPUT_PREFIX])
    return cmd, sources_str


def parse_host_entry(entry: str) -> dict:
    """theHarvester host entries look like 'sub.example.com:1.2.3.4' or just 'sub.example.com'."""
    if ':' in entry:
        host, ip = entry.split(':', 1)
        return {'host': host.strip(), 'ip': ip.strip()}
    return {'host': entry.strip(), 'ip': None}


async def push_records(domain: str, sources_str: str, data: dict) -> dict:
    """Push individual + summary records to Apify dataset. Returns counts."""
    timestamp = datetime.now(timezone.utc).isoformat()
    counts = {
        'hosts': 0,
        'emails': 0,
        'ips': 0,
        'urls': 0,
        'asns': 0,
        'shodan': 0,
        'people': 0,
    }

    # Hosts (parsed)
    for entry in data.get('hosts', []) or []:
        parsed = parse_host_entry(entry)
        await Actor.push_data({
            'recordType': 'host',
            'domain': domain,
            'host': parsed['host'],
            'ip': parsed['ip'],
            'raw': entry,
            'timestamp': timestamp,
        })
        counts['hosts'] += 1

    # Emails
    for email in data.get('emails', []) or []:
        await Actor.push_data({
            'recordType': 'email',
            'domain': domain,
            'email': email,
            'timestamp': timestamp,
        })
        counts['emails'] += 1

    # IPs
    for ip in data.get('ips', []) or []:
        await Actor.push_data({
            'recordType': 'ip',
            'domain': domain,
            'ip': ip,
            'timestamp': timestamp,
        })
        counts['ips'] += 1

    # URLs (theHarvester key: interesting_urls)
    for url in data.get('interesting_urls', []) or []:
        await Actor.push_data({
            'recordType': 'url',
            'domain': domain,
            'url': url,
            'timestamp': timestamp,
        })
        counts['urls'] += 1

    # ASNs
    for asn in data.get('asns', []) or []:
        await Actor.push_data({
            'recordType': 'asn',
            'domain': domain,
            'asn': asn,
            'timestamp': timestamp,
        })
        counts['asns'] += 1

    # Shodan entries (when -s used)
    for shodan_entry in data.get('shodan', []) or []:
        await Actor.push_data({
            'recordType': 'shodan',
            'domain': domain,
            'shodan': shodan_entry,
            'timestamp': timestamp,
        })
        counts['shodan'] += 1

    # People (some sources return this)
    for person in data.get('people', []) or []:
        await Actor.push_data({
            'recordType': 'person',
            'domain': domain,
            'person': person,
            'timestamp': timestamp,
        })
        counts['people'] += 1

    return counts


async def main() -> None:
    async with Actor:
        Actor.log.info('theHarvester OSINT Actor starting')

        input_data = await Actor.get_input() or {}

        raw_domain = input_data.get('domain')
        if not raw_domain or not str(raw_domain).strip():
            await Actor.fail(status_message='No domain given. Enter just the domain, e.g. itm.edu (not a full link).')
            return

        # Auto-clean pasted input (URL, email, www, port) into a bare domain, then
        # validate it. A pasted URL used to return ~1 result and still say "success";
        # cleaning recovers the full run, validating stops wasted runs on junk input.
        domain = clean_domain(raw_domain)
        if not looks_like_domain(domain):
            await Actor.fail(status_message=(
                f'"{raw_domain}" does not look like a domain. Enter just the domain, '
                f'e.g. itm.edu - no https://, no spaces, no path.'))
            return
        if domain != str(raw_domain).strip().lower():
            Actor.log.info(f'Cleaned input "{raw_domain}" -> "{domain}"')
        input_data['domain'] = domain   # use the cleaned value downstream

        Actor.log.info(f'Target domain: {domain}')

        # Merge any extra/advanced API keys (single JSON box) into the flat input so
        # the standard per-service mapping picks them up. Lets us keep only the common
        # keys as named fields while still supporting all 40 providers via one box.
        extra_keys = input_data.get('extraApiKeys')
        if extra_keys:
            if isinstance(extra_keys, str):
                try:
                    extra_keys = json.loads(extra_keys)
                except json.JSONDecodeError:
                    Actor.log.warning('extraApiKeys is not valid JSON - ignoring it')
                    extra_keys = {}
            if isinstance(extra_keys, dict):
                for k, v in extra_keys.items():
                    if v and not input_data.get(k):
                        input_data[k] = v

        # Configure API keys
        api_key_count = build_api_keys_file(input_data)

        # Build and log command
        cmd, sources_str = build_command(input_data)
        Actor.log.info(f'Sources: {sources_str}')
        Actor.log.info(f'Command: {" ".join(cmd)}')

        timeout = int(input_data.get('timeout', 1800))  # default 30 min

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            await Actor.fail(status_message=f'theHarvester timed out after {timeout}s')
            return
        except FileNotFoundError as e:
            await Actor.fail(status_message=f'theHarvester binary not found: {e}')
            return

        Actor.log.info(f'theHarvester exit code: {result.returncode} (stdout {len(result.stdout or "")} chars, stderr {len(result.stderr or "")} chars)')

        # Surface the last interesting lines of stdout - theHarvester prints its summary near the end
        if result.stdout:
            stdout_lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
            for line in stdout_lines[-30:]:
                Actor.log.info(line)
        if result.stderr:
            for line in [ln for ln in result.stderr.splitlines() if ln.strip()][-20:]:
                Actor.log.warning(line)

        if result.returncode != 0:
            Actor.log.error(f'theHarvester exited with code {result.returncode}')

        # Parse output
        json_path = f'{OUTPUT_PREFIX}.json'
        if not os.path.exists(json_path):
            Actor.log.error(f'No JSON output found at {json_path}')
            await Actor.set_status_message(
                f'No output produced for {domain}. The domain may be unreachable, or every '
                f'selected source failed. Check the domain and try the free default sources.')
            await Actor.push_data({
                'recordType': 'summary',
                'domain': domain,
                'sources': sources_str,
                'apiKeysConfigured': api_key_count,
                'success': False,
                'error': 'theHarvester produced no JSON output',
                'exitCode': result.returncode,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
            return

        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            Actor.log.error(f'Failed to parse JSON output: {e}')
            await Actor.push_data({
                'recordType': 'summary',
                'domain': domain,
                'sources': sources_str,
                'apiKeysConfigured': api_key_count,
                'success': False,
                'error': f'JSON parse failed: {e}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
            return

        # Push individual records first (helps with Apify table view + billing)
        counts = await push_records(domain, sources_str, data)
        total_findings = sum(counts.values())

        # Tell the user clearly what happened. A 0-result run must NOT look identical
        # to a good one - that silent-empty case is the #1 "it gave me nothing" churn.
        if total_findings == 0:
            note = (f'0 results for {domain}. Check the domain is spelled correctly and is a '
                    f'real, public site. Try the root domain without "www", or add premium '
                    f'sources / API keys for deeper coverage.')
            Actor.log.warning(note)
            await Actor.set_status_message(note)
        else:
            note = None
            await Actor.set_status_message(
                f'Found {total_findings} records for {domain}: '
                f"{counts['hosts']} subdomains, {counts['emails']} emails, {counts['ips']} IPs.")

        # Push summary record last
        await Actor.push_data({
            'recordType': 'summary',
            'domain': domain,
            'sources': sources_str,
            'apiKeysConfigured': api_key_count,
            'success': True,
            'foundAnything': total_findings > 0,
            'message': note,
            'counts': counts,
            'cmd': data.get('cmd'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

        Actor.log.info(f'Results summary for {domain}: {counts}')
        Actor.log.info('Actor completed successfully')


if __name__ == '__main__':
    asyncio.run(main())
