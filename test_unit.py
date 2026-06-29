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
apify_stub.Actor = _Actor()
sys.modules['apify'] = apify_stub

# Now import the wrapper
sys.path.insert(0, os.path.dirname(__file__))
from src.main import (build_command, parse_host_entry, build_api_keys_file,
                      API_KEY_FIELDS, CONFIG_DIR, clean_domain, looks_like_domain)

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
# Per upstream api-keys.yaml: 35 services
upstream_services = {
    'bevigil', 'bitbucket', 'brave', 'bufferoverun', 'builtwith',
    'censys', 'chaos', 'criminalip', 'dehashed', 'dnsdumpster',
    'dymo', 'fofa', 'fullhunt', 'github', 'hackertarget',
    'haveibeenpwned', 'hunter', 'hunterhow', 'intelx', 'leakix',
    'leaklookup', 'mojeek', 'netlas', 'onyphe', 'pentestTools',
    'projectDiscovery', 'rocketreach', 'securityscorecard', 'securityTrails',
    'shodan', 'subdomainfinderc99', 'tomba', 'venacus', 'virustotal',
    'whoisxml', 'windvane', 'zoomeye'
}
covered = set(API_KEY_FIELDS.keys())
missing = upstream_services - covered
extra = covered - upstream_services
print(f'  Upstream services: {len(upstream_services)}')
print(f'  Wrapper covers:    {len(covered)}')
print(f'  Missing (gaps):    {sorted(missing)}')
print(f'  Extra (wrapper-only): {sorted(extra)}')
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
print('ALL UNIT TESTS PASS ✓')
