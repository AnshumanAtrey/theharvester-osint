"""Unit test the pure helper functions in src/main.py — no Apify SDK needed."""
import sys, types, os, tempfile

# Stub the apify module so importing src.main doesn't pull in the real SDK
apify_stub = types.ModuleType('apify')
class _ActorLog:
    def info(self, m): print(f'[INFO ] {m}')
    def warning(self, m): print(f'[WARN ] {m}')
    def error(self, m): print(f'[ERROR] {m}')
class _Actor:
    log = _ActorLog()
    rows, kv = [], {}
    async def push_data(self, row): self.rows.append(row)
    async def set_value(self, key, value, content_type=None): self.kv[key] = (value, content_type)
apify_stub.Actor = _Actor()
sys.modules['apify'] = apify_stub

# Now import the wrapper
sys.path.insert(0, os.path.dirname(__file__))
from src.main import (build_command, parse_host_entry, build_api_keys_file,
                      API_KEY_FIELDS, CONFIG_DIR, clean_domain, looks_like_domain,
                      resolve_hosts, default_api_keys, normalize_input, InputError,
                      key_sources, fit_timeout, push_records, save_files, OUTPUT_PREFIX, SCREENSHOT_DIR)

import yaml
import shutil

print('=' * 60)
print('TEST 1: build_command with minimal input')
print('=' * 60)
cmd, src = build_command({'domain': 'example.com'})
assert cmd[:3] == ['theHarvester', '-d', 'example.com'], cmd
assert '-b' in cmd
assert 'crtsh,hackertarget,rapiddns,certspotter' in cmd  # default (matches schema)
print(f'  cmd: {cmd}')
print(f'  sources: {src}')
print('  ✓ OK')

print()
print('=' * 60)
print('TEST 2: build_command with all flags')
print('=' * 60)
cmd, src = build_command({
    'domain': 'github.com',
    'sources': ['crtsh', 'shodan', 'github-code'],
    'limit': 1000,
    'start': 50,
    'dnsLookup': True,
    'dnsBrute': True,
    'dnsResolve': '8.8.8.8',
    'dnsServer': '1.1.1.1',
    'shodan': True,
    'takeOver': True,
    'screenshot': True,
    'apiScan': True,
    'wordlist': '/opt/wordlist.txt',
    'useProxies': True,
    'quiet': True,
})
print(f'  cmd: {cmd}')
flags_present = set(cmd)
for required in ['-n', '-c', '-r', '-e', '-s', '-t', '--screenshot', '-a', '-w', '-p', '-q', '-l', '-S']:
    assert required in flags_present, f'Missing flag: {required}'
print('  ✓ All 13 flags present')

print()
print('=' * 60)
print('TEST 3: parse_host_entry')
print('=' * 60)
tests = [
    ('sub.example.com:1.2.3.4', {'host': 'sub.example.com', 'ip': '1.2.3.4'}),
    ('plain.example.com', {'host': 'plain.example.com', 'ip': None}),
    ('  spaced.example.com:5.6.7.8  ', {'host': 'spaced.example.com', 'ip': '5.6.7.8'}),
]
for inp, expected in tests:
    got = parse_host_entry(inp)
    assert got == expected, f'parse_host_entry({inp!r}) -> {got}, expected {expected}'
    print(f'  {inp!r} -> {got}')
print('  ✓ OK')

print()
print('=' * 60)
print('TEST 4: build_api_keys_file (uses ~/.theHarvester/)')
print('=' * 60)
# Backup existing if any
backup_path = None
existing = CONFIG_DIR / 'api-keys.yaml'
if existing.exists():
    backup_path = existing.with_suffix('.yaml.bak.test')
    shutil.copy(existing, backup_path)
    print(f'  (backed up existing {existing} → {backup_path})')

try:
    count = build_api_keys_file({
        'shodanApiKey': 'fake-shodan-key',
        'censysApiId': 'censys-id',
        'censysApiSecret': 'censys-secret',
        'githubToken': 'gh-token-123',
        'tombaKey': 'tomba-k',
        'tombaSecret': 'tomba-s',
        'hibpApiKey': 'hibp-k',  # newly added field
        'mojeekApiKey': 'mojeek-k',  # newly added field
    })
    assert count == 6, f'Expected 6 distinct services (censys id+secret=1, tomba k+s=1), got {count}'
    print(f'  Services configured: {count}')

    with open(existing) as f:
        contents = yaml.safe_load(f)
    apikeys = contents['apikeys']
    assert apikeys['shodan']['key'] == 'fake-shodan-key'
    assert apikeys['censys']['id'] == 'censys-id'
    assert apikeys['censys']['secret'] == 'censys-secret'
    assert apikeys['github']['key'] == 'gh-token-123'
    assert apikeys['tomba']['key'] == 'tomba-k'
    assert apikeys['tomba']['secret'] == 'tomba-s'
    assert apikeys['haveibeenpwned']['key'] == 'hibp-k'
    assert apikeys['mojeek']['key'] == 'mojeek-k'
    print('  ✓ All key mappings correct (shodan, censys id+secret, github, tomba k+s, HIBP, mojeek)')
finally:
    if backup_path:
        shutil.move(backup_path, existing)
        print(f'  (restored backup)')
    else:
        existing.unlink(missing_ok=True)

print()
print('=' * 60)
print('TEST 5: API_KEY_FIELDS covers all upstream services')
print('=' * 60)
# Compare with the api-keys.yaml of the installed theHarvester, so this never goes stale.
upstream_services = set(default_api_keys())
if not upstream_services:
    print('  (theHarvester not installed here - skipped)')
else:
    covered = set(API_KEY_FIELDS.keys())
    missing = upstream_services - covered
    print(f'  Upstream services: {len(upstream_services)}  Wrapper covers: {len(covered)}')
    print(f'  Missing (gaps): {sorted(missing)}  Wrapper-only: {sorted(covered - upstream_services)}')
    assert not missing, f'API key coverage gap: {missing}'
    print('  ✓ Full API key coverage')

print()
print('=' * 60)
print('TEST 6: clean_domain auto-cleans pasted input')
print('=' * 60)
clean_cases = {
    'https://www.itm.edu/': 'itm.edu',
    'http://example.com/path?q=1': 'example.com',
    'www.example.com': 'example.com',
    'example.com': 'example.com',
    'EXAMPLE.COM': 'example.com',
    'sub.example.com': 'sub.example.com',      # keep real subdomain
    'jane.doe@example.com': 'example.com',      # email -> domain
    'example.com:8080': 'example.com',          # strip port
    '  example.com  ': 'example.com',
    'https://x.co:443/a/b?x=1#frag': 'x.co',
    '1.2.3.4': '1.2.3.4',                       # IP untouched
}
for raw, want in clean_cases.items():
    got = clean_domain(raw)
    assert got == want, f'clean_domain({raw!r}) -> {got!r}, expected {want!r}'
print(f'  ✓ {len(clean_cases)} clean cases pass (URL/email/www/port/IP all handled)')

print()
print('=' * 60)
print('TEST 7: looks_like_domain validation gate')
print('=' * 60)
for s in ['itm.edu', 'sub.example.com', 'example.co.uk', '1.2.3.4', 'xn--80ak6aa92e.com']:
    assert looks_like_domain(s), f'should be valid: {s!r}'
for s in ['foo bar baz', 'justtext', '', 'http://', '...', '@@@', 'example', 'a..b.com', ' ']:
    assert not looks_like_domain(s), f'should be invalid: {s!r}'
print('  ✓ Accepts domains + IPs, rejects spaces/junk/bare words')

print()
print('=' * 60)
print('TEST 8: resolve_hosts tags live vs dead names')
print('=' * 60)
import asyncio
got = asyncio.run(resolve_hosts(['localhost', 'no-such-host.invalid', 'localhost', 'bad..name']))
assert got == {'localhost': True, 'no-such-host.invalid': False, 'bad..name': False}, got
print(f'  {got}')
print('  ✓ Live name True, unresolvable/malformed False, duplicates collapsed')

print()
print('=' * 60)
print('TEST 9: normalize_input - one field, bad formats, soft fixes')
print('=' * 60)
SUP = {'crtsh', 'hackertarget', 'rapiddns', 'certspotter', 'virustotal', 'otx', 'github-code', 'shodan', 'securityTrails', 'chaos'}
KEYED = key_sources({'virustotal': {}, 'shodan': {}, 'github': {}, 'hackertarget': {}, 'securityTrails': {}, 'projectDiscovery': {}})
assert KEYED['chaos'] == 'projectDiscovery' and KEYED['github-code'] == 'github' and 'hackertarget' not in KEYED

# Non-tech user: only the website -> complete input, no notes.
inp, notes = normalize_input({'domain': 'tesla.com'}, SUP, KEYED)
assert inp['domain'] == 'tesla.com' and inp['sources'] == ['crtsh', 'hackertarget', 'rapiddns', 'certspotter']
assert (inp['limit'], inp['start'], inp['timeout'], inp['quiet'], inp['dnsBrute']) == (500, 0, 1800, True, False)
assert notes == [], notes

# Platform-filled nulls (API/agents) are fine.
inp, notes = normalize_input({'domain': 'tesla.com', 'shodanApiKey': None, 'extraApiKeys': None, 'dnsServer': None, 'sources': None}, SUP, KEYED)
assert notes == [] and inp['sources'][0] == 'crtsh', notes

# Domain from an alias field, a pasted link, several at once.
inp, notes = normalize_input({'url': 'https://www.Tesla.com/models?x=1'}, SUP, KEYED)
assert inp['domain'] == 'tesla.com' and any('Cleaned' in n for n in notes)
inp, notes = normalize_input({'domain': 'a.com, b.com\nc.com'}, SUP, KEYED)
assert inp['domain'] == 'a.com' and any('skipped 2 more' in n for n in notes)
inp, _ = normalize_input({'domains': ['x.org', 'y.org']}, SUP, KEYED)
assert inp['domain'] == 'x.org'

# Unusable domain: the only hard failures.
for bad in [{}, {'domain': ''}, {'domain': '   '}, {'domain': 'not a domain'}, {'domain': 'justtext'}]:
    try:
        normalize_input(bad, SUP, KEYED); raise SystemExit(f'should fail: {bad}')
    except InputError as e:
        assert 'itm.edu' in str(e), e

# Sources: typed names, commas, aliases, unknowns, key warnings.
inp, notes = normalize_input({'domain': 'x.com', 'sources': 'crt.sh, VirusTotal, bogus, AlienVault, GitHub'}, SUP, KEYED)
assert inp['sources'] == ['crtsh', 'virustotal', 'otx', 'github-code'], inp['sources']
assert any('bogus' in n for n in notes) and any('No key for virustotal, github-code' in n for n in notes), notes
inp, notes = normalize_input({'domain': 'x.com', 'sources': ['nope', 'nada']}, SUP, KEYED)
assert inp['sources'] == ['crtsh', 'hackertarget', 'rapiddns', 'certspotter'] and any('free defaults' in n for n in notes)
inp, notes = normalize_input({'domain': 'x.com', 'sources': ['chaos'], 'chaosApiKey': 'k'}, SUP, KEYED)
assert not any('No key' in n for n in notes), notes   # chaos reads the ProjectDiscovery key, which chaosApiKey fills

# Numbers and yes/no given in loose forms.
inp, notes = normalize_input({'domain': 'x.com', 'limit': 'abc', 'timeout': 5, 'start': '-3'}, SUP, KEYED)
assert (inp['limit'], inp['timeout'], inp['start']) == (500, 60, 0) and len(notes) == 3, notes
inp, notes = normalize_input({'domain': 'x.com', 'limit': '200', 'dnsLookup': 'yes', 'quiet': 'no'}, SUP, KEYED)
assert (inp['limit'], inp['dnsLookup'], inp['quiet']) == (200, True, False) and notes == [], notes
inp, notes = normalize_input({'domain': 'x.com', 'limit': 99999, 'dnsBrute': 'maybe'}, SUP, KEYED)
assert inp['limit'] == 10000 and inp['dnsBrute'] is False and len(notes) == 2, notes

# Features that need a missing key are switched off; keys are trimmed; extra keys merged.
inp, notes = normalize_input({'domain': 'x.com', 'shodan': True}, SUP, KEYED)
assert inp['shodan'] is False and any('Shodan key' in n for n in notes)
inp, notes = normalize_input({'domain': 'x.com', 'shodan': True, 'shodanApiKey': '  s-key  '}, SUP, KEYED)
assert inp['shodan'] is True and inp['shodanApiKey'] == 's-key'
inp, notes = normalize_input({'domain': 'x.com', 'extraApiKeys': '{"netlasApiKey": " n ", "madeUpKey": "z"}'}, SUP, KEYED)
assert inp['netlasApiKey'] == 'n' and any('madeUpKey' in n for n in notes)
inp, notes = normalize_input({'domain': 'x.com', 'extraApiKeys': '{broken'}, SUP, KEYED)
assert any('not valid JSON' in n for n in notes)

# Technical strings: kept only when usable.
inp, notes = normalize_input({'domain': 'x.com', 'dnsServer': '8.8.8.8', 'dnsResolve': '1.1.1.1, 8.8.4.4'}, SUP, KEYED)
assert inp['dnsServer'] == '8.8.8.8' and inp['dnsResolve'] == '1.1.1.1,8.8.4.4' and notes == [], notes
inp, notes = normalize_input({'domain': 'x.com', 'dnsServer': 'dns.google', 'dnsResolve': 'foo', 'wordlist': '/nope.txt'}, SUP, KEYED)
assert 'dnsServer' not in inp and 'dnsResolve' not in inp and 'wordlist' not in inp and len(notes) == 3, notes

# Typos in field names are reported.
inp, notes = normalize_input({'domain': 'x.com', 'limt': 5}, SUP, KEYED)
assert any('limt' in n for n in notes), notes
print('  ✓ one-field run, nulls, aliases, pasted links, loose numbers/booleans, unknown sources, missing keys, typos')

print()
print('=' * 60)
print('TEST 10: fit_timeout keeps the search inside the run limit')
print('=' * 60)
from datetime import datetime, timedelta, timezone
os.environ['ACTOR_TIMEOUT_AT'] = (datetime.now(timezone.utc) + timedelta(seconds=600)).isoformat().replace('+00:00', 'Z')
n = []
t = fit_timeout(1800, n)
assert 500 <= t <= 540 and n, (t, n)
assert fit_timeout(120, []) == 120
del os.environ['ACTOR_TIMEOUT_AT']
assert fit_timeout(1800, []) == 1800
print(f'  ✓ 1800s lowered to {t}s with 10 min of run left; untouched when it fits or no deadline')

print()
print('=' * 60)
print('TEST 11: every theHarvester result is passed through, files saved as-is')
print('=' * 60)
import asyncio, pathlib
A = apify_stub.Actor
data = {'cmd': '-d x.com', 'hosts': ['localhost'], 'emails': ['a@x.com'], 'shodan': [],
        'vhosts': ['v.x.com'], 'trello_urls': ['https://trello.com/b/1'], 'twitter_people': ['@x'],
        'linkedin_people': ['Jane'], 'linkedin_links': ['https://linkedin.com/in/j'],
        'takeover_results': {'old.x.com': 'github-pages'}, 'future_key': ['something new']}
counts = asyncio.run(push_records('x.com', 'crtsh', data))
kinds = [r['recordType'] for r in A.rows]
for k in ['host', 'email', 'vhosts', 'trello_urls', 'twitter_people', 'linkedin_people', 'linkedin_links', 'takeover_results', 'future_key']:
    assert k in kinds, (k, kinds)
take = next(r for r in A.rows if r['recordType'] == 'takeover_results')
assert take['key'] == 'old.x.com' and take['value'] == 'github-pages', take
assert counts['takeover_results'] == 1 and counts['future_key'] == 1 and 'cmd' not in kinds
print(f'  ✓ {len(A.rows)} rows, recordTypes: {sorted(set(kinds))}')

pathlib.Path(OUTPUT_PREFIX + '.json').write_text('{}'); pathlib.Path(OUTPUT_PREFIX + '.xml').write_text('<x/>')
os.makedirs(SCREENSHOT_DIR, exist_ok=True); pathlib.Path(SCREENSHOT_DIR, 'v.x.com.png').write_bytes(b'png')
try:
    keys = asyncio.run(save_files('[*] API Endpoints found: 1\n    - /api'))
    assert keys == ['theharvester-output.txt', 'report.json', 'report.xml', 'screenshot-v.x.com.png'], keys
    assert A.kv['report.xml'][1] == 'application/xml' and A.kv['screenshot-v.x.com.png'][1] == 'image/png'
    print(f'  ✓ saved {keys}')
finally:
    for f in [OUTPUT_PREFIX + '.json', OUTPUT_PREFIX + '.xml']: pathlib.Path(f).unlink(missing_ok=True)
    shutil.rmtree(SCREENSHOT_DIR, ignore_errors=True)

print()
print('ALL UNIT TESTS PASS ✓')
