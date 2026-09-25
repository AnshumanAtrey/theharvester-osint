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
    'projectDiscovery':   [('projectdiscoveryApiKey', 'key'), ('chaosApiKey', 'key')],  # chaos reads this key
    'rocketreach':        [('rocketreachApiKey', 'key')],
    'securityscorecard':  [('securityscorecardApiKey', 'key')],
    'securityTrails':     [('securitytrailsApiKey', 'key')],
    'sherlockeye':        [('sherlockeyeApiKey', 'key')],
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


def default_api_keys() -> dict:
    """The api-keys.yaml shipped with the installed theHarvester: every service, keys empty.

    theHarvester looks up its service's entry even for keyless sources, so a file
    missing an entry breaks that source (an empty `apikeys: {}` made hackertarget,
    a default free source, return nothing). Starting from the shipped file keeps
    every service present and follows upstream as it adds services.
    """
    try:
        from importlib.resources import files
        text = (files('theHarvester') / 'data' / 'api-keys.yaml').read_text()
        return (yaml.safe_load(text) or {}).get('apikeys') or {}
    except Exception:
        return {}


def build_api_keys_file(input_data: dict) -> int:
    """Write ~/.theHarvester/api-keys.yaml: shipped defaults plus the user's keys. Returns count of services configured."""
    api_keys = default_api_keys()
    configured = []
    for service, fields in API_KEY_FIELDS.items():
        for input_key, yaml_subkey in fields:
            value = input_data.get(input_key)
            if value:
                entry = api_keys.get(service)
                api_keys[service] = entry = entry if isinstance(entry, dict) else {}
                entry[yaml_subkey] = value
                if service not in configured:
                    configured.append(service)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_DIR / 'api-keys.yaml', 'w') as f:
        yaml.dump({'apikeys': api_keys}, f, default_flow_style=False)
    if configured:
        Actor.log.info(f'API keys configured for {len(configured)} services: {sorted(configured)}')
    else:
        Actor.log.info('No API keys provided - running with free sources only')
    return len(configured)


FREE_DEFAULT_SOURCES = ['crtsh', 'hackertarget', 'rapiddns', 'certspotter']
# Common ways people name a source, keyed by _norm(); exact names in any case/punctuation match anyway.
SOURCE_ALIASES = {
    'alienvault': 'otx', 'alienvaultotx': 'otx', 'github': 'github-code', 'githubcode': 'github-code',
    'wayback': 'waybackarchive', 'waybackmachine': 'waybackarchive', 'internetdb': 'shodanInternetDB',
    'hibp': 'haveibeenpwned', 'c99': 'subdomainfinderc99', 'hunterio': 'hunter', 'hunterhow': 'hunterhow',
    'bravesearch': 'brave', 'criminalip': 'criminalip', 'certificatetransparency': 'crtsh',
}
BOOL_FIELDS = {'dnsLookup': False, 'dnsBrute': False, 'takeOver': False, 'screenshot': False,
               'shodan': False, 'apiScan': False, 'useProxies': False, 'quiet': True}
DOMAIN_ALIASES = ('domain', 'domains', 'url', 'website', 'target', 'email')
KEY_INPUTS = {k for fields in API_KEY_FIELDS.values() for k, _ in fields}
SCHEMA_PATH = Path(__file__).resolve().parent.parent / '.actor' / 'INPUT_SCHEMA.json'


class InputError(Exception):
    """Input that cannot be read one obvious way. The message tells the user what to type."""


def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(s).lower())


def _split(v) -> list[str]:
    """A list, or a string separated by commas/newlines/semicolons, as clean non-empty strings."""
    items = v if isinstance(v, list) else re.split(r'[,\n;]+', str(v))
    return [str(x).strip() for x in items if x is not None and str(x).strip()]


def _as_bool(v, default: bool, name: str, notes: list) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ('true', 'yes', 'y', '1', 'on'):
        return True
    if s in ('false', 'no', 'n', '0', 'off', ''):
        return False
    notes.append(f'{name}: "{v}" is not yes/no, so the default ({default}) was used.')
    return default


def _as_int(v, default: int, lo: int, hi: int | None, name: str, notes: list) -> int:
    if v is None or (isinstance(v, str) and not v.strip()):
        return default
    try:
        n = int(float(str(v).strip()))
    except ValueError:
        notes.append(f'{name}: "{v}" is not a number, so the default ({default}) was used.')
        return default
    fixed = max(lo, n if hi is None else min(hi, n))
    if fixed != n:
        notes.append(f'{name}: {n} is out of range, so {fixed} was used.')
    return fixed


def _is_ip_address(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def supported_sources() -> set[str] | None:
    """Source names the installed theHarvester accepts, read from its -h text.

    One unknown name makes theHarvester reject the whole run, so names are
    checked against this list first. Returns None if the help text can't be
    read, and then names are passed through unchecked.
    """
    try:
        text = subprocess.run(['theHarvester', '-h'], capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return None
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if '--source' in line:
            block = [line.split('SOURCE', 1)[-1]]
            for nxt in lines[i + 1:]:
                if re.match(r'\s+-', nxt):
                    break
                block.append(nxt)
            names = set(re.findall(r'[A-Za-z][\w-]*', ' '.join(block)))
            return names if 'crtsh' in names else None
    return None


def schema_sources() -> set[str] | None:
    """Fallback source list: the names offered in the input schema."""
    try:
        return set(json.loads(SCHEMA_PATH.read_text())['properties']['sources']['items']['enumSuggestedValues'])
    except Exception:
        return None


def key_sources(defaults: dict) -> dict[str, str]:
    """Map each source that needs a key to its api-keys.yaml service name.

    Derived from the shipped api-keys.yaml, so it follows upstream. hackertarget
    has an optional key and works without one, so it is left out.
    """
    services = {s.lower(): s for s in defaults if s != 'hackertarget'}
    out = {name: services[name] for name in services}
    out['github-code'] = services.get('github', 'github')
    out['chaos'] = services.get('projectdiscovery', 'projectDiscovery')
    return out


def normalize_input(raw: dict, supported: set[str] | None = None, keyed: dict[str, str] | None = None) -> tuple[dict, list[str]]:
    """Turn whatever the user sent into a complete, valid input, plus plain-language notes.

    Every field gets a working default. Anything that can be read one obvious way
    is fixed and noted; only an unusable domain raises InputError.
    """
    raw = dict(raw or {})
    notes: list[str] = []
    inp: dict = {}

    # Domain: accept the common alternatives, take the first if several.
    value = next((raw.get(k) for k in DOMAIN_ALIASES if raw.get(k)), None)
    candidates = _split(value) if value else []
    if not candidates:
        raise InputError('No website given. Enter just the website to research, e.g. itm.edu.')
    if len(candidates) > 1:
        notes.append(f'One website per run: used "{candidates[0]}" and skipped {len(candidates) - 1} more.')
    domain = clean_domain(candidates[0].split()[0])
    if not looks_like_domain(domain):
        raise InputError(f'"{candidates[0]}" does not look like a website. Enter just the domain, '
                         f'e.g. itm.edu - no spaces, no path.')
    if domain != candidates[0].strip().lower():
        notes.append(f'Cleaned "{candidates[0]}" to "{domain}".')
    inp['domain'] = domain

    # Sources: names in any case/punctuation, aliases, commas; unknown names skipped.
    wanted = _split(raw['sources']) if raw.get('sources') else []
    lookup = {_norm(s): s for s in (supported or [])}
    chosen, unknown = [], []
    for name in wanted:
        n = _norm(name)
        hit = lookup.get(n) or lookup.get(_norm(SOURCE_ALIASES.get(n, ''))) if supported else (SOURCE_ALIASES.get(n) or name)
        if hit and hit not in chosen:
            chosen.append(hit)
        elif not hit:
            unknown.append(name)
    if unknown:
        notes.append(f'Skipped unknown source(s): {", ".join(unknown)}.')
    if not chosen:
        if wanted:
            notes.append('None of the chosen sources are available, so the free defaults were used.')
        chosen = list(FREE_DEFAULT_SOURCES)
    inp['sources'] = chosen

    inp['limit'] = _as_int(raw.get('limit'), 500, 1, 10000, 'Results per source (limit)', notes)
    inp['start'] = _as_int(raw.get('start'), 0, 0, None, 'Skip first results (start)', notes)
    inp['timeout'] = _as_int(raw.get('timeout'), 1800, 60, 3600, 'Time limit (timeout)', notes)
    for field, default in BOOL_FIELDS.items():
        inp[field] = _as_bool(raw.get(field), default, field, notes)

    # API keys: trimmed strings; the extra-keys box merged in, unknown names noted.
    for k in KEY_INPUTS:
        v = raw.get(k)
        if v is not None and str(v).strip():
            inp[k] = str(v).strip()
    extra = raw.get('extraApiKeys')
    if isinstance(extra, str) and extra.strip():
        try:
            extra = json.loads(extra)
        except json.JSONDecodeError:
            notes.append('Other keys (extraApiKeys) is not valid JSON, so it was ignored.')
            extra = None
    if extra and not isinstance(extra, dict):
        notes.append('Other keys (extraApiKeys) must be an object like {"netlasApiKey": "..."}, so it was ignored.')
        extra = None
    if extra:
        bad = sorted(k for k in extra if k not in KEY_INPUTS)
        if bad:
            notes.append(f'Other keys: ignored unknown name(s) {", ".join(bad)}.')
        for k, v in extra.items():
            if k in KEY_INPUTS and v is not None and str(v).strip() and not inp.get(k):
                inp[k] = str(v).strip()

    # Features that need something they don't have are switched off, not left to fail.
    if inp['shodan'] and not inp.get('shodanApiKey'):
        inp['shodan'] = False
        notes.append('Add Shodan details was switched off: it needs your Shodan key.')
    missing = []
    for src in inp['sources']:
        service = (keyed or {}).get(src.lower())
        fields = API_KEY_FIELDS.get(service, [])
        if service and not any(inp.get(k) for k, _ in fields):
            missing.append(src)
    if missing:
        notes.append(f'No key for {", ".join(missing)}: these return nothing until you add a key in Your own keys.')

    # Optional technical strings: kept only if usable.
    server = str(raw.get('dnsServer') or '').strip()
    if server:
        if _is_ip_address(server):
            inp['dnsServer'] = server
        else:
            notes.append(f'Lookup server (dnsServer): "{server}" is not an IP address, so the default was used.')
    resolve = str(raw.get('dnsResolve') or '').strip()
    if resolve:
        ips = _split(resolve)
        if os.path.isfile(resolve) or (ips and all(_is_ip_address(x) for x in ips)):
            inp['dnsResolve'] = resolve if os.path.isfile(resolve) else ','.join(ips)
        else:
            notes.append(f'Own lookup servers (dnsResolve): "{resolve}" is neither IP addresses nor a file, so the default was used.')
    wordlist = str(raw.get('wordlist') or '').strip()
    if wordlist:
        if os.path.isfile(wordlist):
            inp['wordlist'] = wordlist
        else:
            notes.append(f'Word list file (wordlist): "{wordlist}" does not exist, so the built-in list was used.')

    # Typos in field names would otherwise be ignored silently.
    try:
        known = set(json.loads(SCHEMA_PATH.read_text())['properties'])
    except Exception:
        known = None
    if known is not None:
        stray = sorted(k for k in raw if k not in known and k not in DOMAIN_ALIASES and k not in KEY_INPUTS)
        if stray:
            notes.append(f'Ignored unknown field(s): {", ".join(stray)}.')

    return inp, notes


def fit_timeout(timeout: int, notes: list) -> int:
    """Keep theHarvester's time limit inside the run's own, so results are always pushed before Apify stops the run."""
    deadline = os.environ.get('ACTOR_TIMEOUT_AT')
    if not deadline:
        return timeout
    try:
        end = datetime.fromisoformat(deadline.replace('Z', '+00:00'))
    except ValueError:
        return timeout
    room = int((end - datetime.now(timezone.utc)).total_seconds()) - 60  # leave a minute to push results
    if room < timeout:
        fitted = max(30, room)
        notes.append(f'Time limit lowered from {timeout}s to {fitted}s to fit inside the run\'s own time limit.')
        return fitted
    return timeout


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


async def resolve_hosts(hosts: list[str], timeout: float = 3.0, concurrency: int = 50) -> dict[str, bool]:
    """Map each hostname to whether it resolves in public DNS right now.

    Certificate-transparency sources return many retired or internal-only names;
    this lets users tell live subdomains from historical ones. Cost is a few
    seconds for hundreds of hosts.
    """
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)

    async def check(host: str) -> bool:
        async with sem:
            try:
                await asyncio.wait_for(loop.getaddrinfo(host, None), timeout)
                return True
            except (OSError, asyncio.TimeoutError, UnicodeError):
                return False

    unique = sorted(set(hosts))
    results = await asyncio.gather(*(check(h) for h in unique))
    return dict(zip(unique, results))


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
        'liveHosts': 0,
    }

    # Hosts (parsed), each tagged with whether it resolves in DNS now
    host_entries = [(entry, parse_host_entry(entry)) for entry in data.get('hosts', []) or []]
    live = await resolve_hosts([p['host'] for _, p in host_entries])
    for entry, parsed in host_entries:
        resolves = live.get(parsed['host'], False)
        await Actor.push_data({
            'recordType': 'host',
            'domain': domain,
            'host': parsed['host'],
            'ip': parsed['ip'],
            'resolves': resolves,
            'raw': entry,
            'timestamp': timestamp,
        })
        counts['hosts'] += 1
        counts['liveHosts'] += resolves

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

        raw_input = await Actor.get_input() or {}
        defaults = default_api_keys()
        try:
            input_data, notes = normalize_input(raw_input, supported_sources() or schema_sources(), key_sources(defaults))
        except InputError as e:
            # Nothing was pushed, so a bad input costs the user $0.
            await Actor.fail(status_message=str(e))
            return
        # The platform fills the 1800s default into every input, and the default run limit is
        # also 1800s, so fitting the default is routine and silent; a user-chosen limit gets a note.
        input_data['timeout'] = fit_timeout(input_data['timeout'], notes if input_data['timeout'] != 1800 else [])
        for note in notes:
            Actor.log.warning(f'Input note: {note}')
        domain = input_data['domain']
        Actor.log.info(f'Target domain: {domain}')

        # Configure API keys
        api_key_count = build_api_keys_file(input_data)

        # Build and log command
        cmd, sources_str = build_command(input_data)
        Actor.log.info(f'Sources: {sources_str}')
        Actor.log.info(f'Command: {" ".join(cmd)}')

        timeout = input_data['timeout']

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            await Actor.fail(status_message=(
                f'The search hit the {timeout}s time limit before finishing, so nothing was charged. '
                f'Pick fewer sources, lower Results per source, or raise Time limit.'))
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
                'inputNotes': notes,
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
                'inputNotes': notes,
                'success': False,
                'error': f'JSON parse failed: {e}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
            return

        # Push individual records first (helps with Apify table view + billing)
        counts = await push_records(domain, sources_str, data)
        total_findings = sum(v for k, v in counts.items() if k != 'liveHosts')  # liveHosts is a subset of hosts

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
                f"{counts['hosts']} subdomains ({counts['liveHosts']} live in DNS), "
                f"{counts['emails']} emails, {counts['ips']} IPs.")

        if notes:
            await Actor.set_status_message(
                f'{note or "Found " + str(total_findings) + " records for " + domain + "."} '
                f'{len(notes)} input note(s): {" ".join(notes)}'[:900])

        # Push summary record last
        await Actor.push_data({
            'recordType': 'summary',
            'domain': domain,
            'sources': sources_str,
            'apiKeysConfigured': api_key_count,
            'success': True,
            'foundAnything': total_findings > 0,
            'inputNotes': notes,
            'message': note,
            'counts': counts,
            'cmd': data.get('cmd'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

        Actor.log.info(f'Results summary for {domain}: {counts}')
        Actor.log.info('Actor completed successfully')


if __name__ == '__main__':
    asyncio.run(main())
