# IOC database

JSON files of known indicators of compromise (IOCs) that clonesafe checks during `vet-repo`.

## Files

| File | Contains |
|---|---|
| [`packages.json`](packages.json) | Known-bad npm packages and specific versions |
| [`domains.json`](domains.json) | Exfil endpoints, C2 infrastructure, stager domains |
| [`github-orgs.json`](github-orgs.json) | GitHub organizations tied to campaigns |
| [`hashes.json`](hashes.json) | SHA256 of specific malicious files |
| [`recruiters.json`](recruiters.json) | Known scam recruiter handles (for use by `job-scam-detector`) |

## Format

Every IOC entry has:

```json
{
  "id": "IOC-YYYY-NNN",
  "identifier": "the thing (package name, domain, org, hash)",
  "type": "package|domain|org|hash|recruiter",
  "first_seen": "YYYY-MM-DD",
  "campaign": "contagious-interview-001|axios-compromise-2026|...",
  "source": "CISA AA24-XXX|Unit 42|Snyk|self-reported|...",
  "source_url": "https://...",
  "description": "one-line what and why",
  "versions": ["1.14.1", "0.30.4"],        // packages only
  "confidence": "high|medium|low"
}
```

## How to add an IOC

1. Open an [IOC submission issue](../.github/ISSUE_TEMPLATE/ioc-submission.md) with details
2. For PRs: add your entry to the right JSON file, include `source` and `source_url`, keep entries sorted alphabetically by `identifier`
3. Do not add IOCs based on hearsay — every entry needs a citable source or a sample in `samples/`

## What NOT to include

- Individual victim data (names, addresses, personal wallet addresses)
- Recruiter identifiers based on nationality, accent, or name origin
- Speculation without evidence
- Repositories of legitimate security researchers even if they contain malware samples (those are samples, not IOCs)

## Freshness

Campaigns rotate infrastructure quickly. An IOC that was valid 6 months ago may now be dormant. We don't remove IOCs — we add `last_verified` dates where possible, and mark confidence. Stale IOCs still have value as historical markers.
