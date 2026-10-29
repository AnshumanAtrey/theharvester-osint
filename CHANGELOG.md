# Changelog

## [1.1.26] - 2026-10-29

### Fixed
- One slow source could lose a whole run. theHarvester waits for every selected source before it prints any result, and its own HTTP timeout is 12 minutes, so a stalled crt.sh (a default source, slow on big domains) held the run past its time limit with nothing printed to deliver. theHarvester now runs through `src/th_entry.py`, which stops any source still searching at 85% of the time limit (60% when extra checks such as DNS brute force still have to run): the other sources' results are printed and delivered, with a note naming how many were stopped. Reproduced with a fake hung crt.sh: killed at 25 s with 0 hosts before, 2 hosts delivered at 5 s after (unit TEST 15).

### Changed
- Store discounts: $0.0027 per record on Scale, $0.0024 on Business and above; Free and Starter stay at $0.003.
- The listing is now synced from the repo by CI (`.actor/store.json`, made from the live listing; the description lost its em dash), and two example tasks are published on the Store.

## [1.1.23] - 2026-10-29

### Added
- An email address typed as the website now says what the run does with it (maps the provider's domain) and links Holehe Email OSINT for the address itself. Three of last week's failed runs were a typed gmail.com address with DNS brute force.

### Fixed
- A run cut off by its time limit during DNS brute force failed with nothing delivered, although theHarvester had already listed its hosts (it writes report.json only after brute force, and its Ctrl+C handler writes nothing). The hosts, IPs, emails and other lists it printed are now read back from its console output and delivered with a note; the run fails only when the cut came before anything was listed. Reproduced: gmail.com with brute force against an unanswering DNS server, 44 hosts listed, 0 delivered before, 44 delivered after.
- The same applies when theHarvester itself is killed before its report, which in a container means the memory limit: the subdomain takeover check on 5,100 gmail.com hosts peaked at 977 MB of 1 GB and was killed (exit code -9). Its listed results are delivered and the note names the likely cause.
- Runs started from Apify's AI assistant could fail after finishing: SDK 3.4.1 rejects the run origin APIFY_AI when it reads back the status message. Now on Apify SDK 4, which accepts every origin.
- A run stopped by its spending limit kept trying to push the rows the platform refused, and then reported every result as found (limit $0.50: 166 rows delivered, "Found 5101 records"). It now stops at the limit, looks up DNS only for the hosts it can deliver, and says how many of the results were delivered and how to get the rest.

## [1.1.2] - 2026-09-25

### Fixed
- HackerTarget, one of the four default free sources, returned nothing on every run: the key file the actor wrote left out its entry. The key file now starts from theHarvester's own and adds your keys.
- `chaosApiKey` was written where theHarvester never reads it; it now fills the ProjectDiscovery key that the Chaos source uses.
- Screenshots never worked: theHarvester takes them with Playwright's own browser, which was never installed in the image (a system Chromium was, which Playwright doesn't use). The image now installs Playwright's browser.
- A run that hit its time limit returned nothing; theHarvester's status lines now stream to the log as it runs, the output so far is saved, and results already written (the results file is saved before the slow API scan) are delivered with a note.
- A long search could be cut off by the run's own time limit with nothing returned; the search now always stops a minute early so results are saved.

### Added
- Nothing theHarvester finds is dropped any more: vhosts, trello_urls, twitter_people, linkedin_people, linkedin_links and takeover_results (plus any key a later release adds) are rows under theHarvester's own names. Before, the takeover check's results were thrown away.
- theHarvester's own output saved unchanged to the key-value store: full console output (the only place API-scan results appear), report.json, report.xml, and screenshots, which were taken but never saved before.
- Every input is checked and soft-fixed with a plain note (log, status message, summary `inputNotes`): numbers or yes/no as text, out-of-range numbers, source names in any form ("crt.sh", "VirusTotal"), unknown sources, typos in field names, invalid lookup server, missing word list, Shodan details without a key. Only a missing or unusable website stops the run, at $0.
- The website can also be given as `url`, `website`, `domains`, `target` or `email`; with several, the first is used.
- Source list is read from the installed theHarvester at run start, so an upstream rename never breaks a run. Added SherlockEye; DNSDumpster and Mojeek now correctly marked as needing a key, Shodan InternetDB as free.
- Plain-words form labels with the field key in brackets, units on number fields, and documented output fields.
- `resolves` on every host record: whether the subdomain answers in public DNS right now. Certificate logs also return retired and internal-only names; this lets users filter to live subdomains. The summary record adds `counts.liveHosts`, and the status message shows the live count.

### Changed
- theHarvester is pinned to a release (4.11.1) and moved forward by a weekly workflow that adapts the Python base image and ships only after a side-by-side smoke test.

## [1.1.1] - 2026-06-29

### Added
- Auto-clean the domain input: a pasted URL, email, `www.` prefix or port is now normalized to a bare domain (so `https://www.itm.edu/` becomes `itm.edu`), recovering full results from input that used to return almost nothing.
- Early input validation: clearly invalid input (spaces, junk, missing dot) now fails fast with a plain-English reason instead of a silent empty run.
- Clear end-of-run status message: every run now reports what it found, and a 0-result run says so explicitly with what to check, instead of looking identical to a successful run.
- `extraApiKeys` input: one JSON box that supplies keys for the 30+ less common premium sources.

### Changed
- Input form simplified from 56 fields to 25: the domain box stands alone, and the rest are grouped into "Search options", "Advanced options", and "API keys (optional)". The 7 most-used API keys keep their own fields; the rest move into `extraApiKeys`. No capability removed.
- Rewrote every field description from CLI-flag shorthand (`-c flag`, `-n flag`) into plain English.
- Repositioned the listing for non-developer users (sales, recruiting, due diligence, fraud) while keeping security and bug-bounty discoverability.

### Fixed
- Default free sources now consistent between the input schema and the runner (crt.sh, HackerTarget, RapidDNS, CertSpotter).
- Removed a dead `dnsResolveAll` code branch that referenced a non-existent input.
- Corrected the unit test that assumed the wrong invocation, and added tests for input cleaning and validation.
- README input table and output example now match what the actor actually accepts and returns.

## [1.0.0] - 2025-11-18

### Added
- Initial release with complete theHarvester CLI feature parity
- Support for 50+ data sources (passive and active)
- API key management for 25+ premium sources
- DNS reconnaissance features (lookup, brute force, resolution)
- Active reconnaissance (Shodan, takeover checks, screenshots)
- JSON output via Apify dataset
- Comprehensive input validation
- Detailed logging and error handling
