# Changelog

## [1.1.2] - 2026-09-25

### Fixed
- HackerTarget, one of the four default free sources, returned nothing on every run: the key file the actor wrote left out its entry. The key file now starts from theHarvester's own and adds your keys.
- `chaosApiKey` was written where theHarvester never reads it; it now fills the ProjectDiscovery key that the Chaos source uses.
- A long search could be cut off by the run's own time limit with nothing returned; the search now always stops a minute early so results are saved.

### Added
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
