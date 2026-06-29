# Changelog

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
