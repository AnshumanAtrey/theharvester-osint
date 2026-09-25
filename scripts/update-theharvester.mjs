#!/usr/bin/env node
/**
 * Move the Dockerfile to a new theHarvester version, adapting the base image.
 *
 * theHarvester is installed from GitHub at a pinned ref. Upstream raises its
 * Python floor without notice (master went to >=3.14 on 2026-08-16 while our
 * base image was 3.13, and unpinned builds failed silently for weeks). This
 * script picks the target ref (REF env, default: latest GitHub release), reads
 * its pyproject.toml `requires-python`, and rewrites the Dockerfile:
 *   - `theHarvester.git@<ref>` -> the target ref
 *   - `FROM apify/actor-python:<ver>` -> kept if it satisfies requires-python,
 *     else the lowest Apify image version on Docker Hub that does.
 * It changes nothing else. Whether the result works is decided by the smoke
 * test in .github/workflows/theharvester-update.yml, not here.
 *
 * Usage: [REF=<tag|branch|sha>] node scripts/update-theharvester.mjs
 * Writes changed/ref/python/current_ref/current_python to $GITHUB_OUTPUT when set.
 * Exits 1 if no Apify base image satisfies the requirement.
 */
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';

const UPSTREAM = 'laramies/theHarvester';
async function get(url, json = true) {
  // The token only goes to the GitHub API (rate limits); never to Docker Hub or raw file hosts.
  const headers = { 'User-Agent': 'theharvester-osint-updater' };
  if (process.env.GH_TOKEN && url.startsWith('https://api.github.com/')) headers.Authorization = `Bearer ${process.env.GH_TOKEN}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return json ? res.json() : res.text();
}

// "3.14" -> [3, 14]
const ver = (s) => s.split('.').slice(0, 2).map(Number);
const cmp = (a, b) => a[0] - b[0] || a[1] - b[1];

// Does Python major.minor `v` satisfy a PEP 440 requires-python spec?
// Handles the operators pyproject files actually use: >=, >, <=, <, ==, !=, ~=, and X.Y.* wildcards.
function satisfies(v, spec) {
  return spec.split(',').map((c) => c.trim()).filter(Boolean).every((clause) => {
    const m = clause.match(/^(>=|<=|==|!=|~=|>|<)\s*([\d.]+)(\.\*)?$/);
    if (!m) throw new Error(`unsupported requires-python clause: ${clause}`);
    const [, op, raw] = m;
    const want = ver(raw);
    const c = cmp(v, want);
    switch (op) {
      case '>=': return c >= 0;
      case '>': return c > 0;
      case '<=': return c <= 0;
      case '<': return c < 0;
      case '==': return c === 0;
      case '!=': return c !== 0;
      case '~=': return c >= 0 && v[0] === want[0];
    }
  });
}

const dockerfile = readFileSync('Dockerfile', 'utf8');
const fromRe = /^FROM apify\/actor-python:(\d+\.\d+)$/m;
const pinRe = /theHarvester\.git@([^\s]+)/;
const currentPython = dockerfile.match(fromRe)?.[1];
const currentRef = dockerfile.match(pinRe)?.[1];
if (!currentPython || !currentRef) throw new Error('Dockerfile no longer has the FROM/pin lines this script rewrites');

const ref = process.env.REF || (await get(`https://api.github.com/repos/${UPSTREAM}/releases/latest`)).tag_name;
const pyproject = await get(`https://raw.githubusercontent.com/${UPSTREAM}/${ref}/pyproject.toml`, false);
const spec = pyproject.match(/^requires-python\s*=\s*"([^"]+)"/m)?.[1];
if (!spec) throw new Error(`no requires-python in ${ref}/pyproject.toml`);

let python = currentPython;
if (!satisfies(ver(currentPython), spec)) {
  const tags = (await get('https://hub.docker.com/v2/repositories/apify/actor-python/tags?page_size=100&name=3.')).results
    .map((t) => t.name).filter((n) => /^\d+\.\d+$/.test(n)).sort((a, b) => cmp(ver(a), ver(b)));
  python = tags.find((t) => satisfies(ver(t), spec));
  if (!python) {
    console.error(`theHarvester ${ref} needs Python ${spec}; Apify publishes only ${tags.join(', ')}`);
    process.exit(1);
  }
}

const changed = ref !== currentRef || python !== currentPython;
if (changed) {
  writeFileSync('Dockerfile', dockerfile
    .replace(fromRe, `FROM apify/actor-python:${python}`)
    .replace(pinRe, `theHarvester.git@${ref}`));
}
console.log(`theHarvester ${currentRef} -> ${ref} (requires-python ${spec}); base image ${currentPython} -> ${python}; changed=${changed}`);

if (process.env.GITHUB_OUTPUT) {
  appendFileSync(process.env.GITHUB_OUTPUT,
    `changed=${changed}\nref=${ref}\npython=${python}\ncurrent_ref=${currentRef}\ncurrent_python=${currentPython}\nspec=${spec}\n`);
}
