---
name: ioc-update
description: Guided flow for adding new indicators of compromise to the clonesafe database. Walks the user through a structured submission, validates the data, produces a PR-ready diff against the relevant iocs/*.json file, and opens an issue/PR if the user wants.
triggers:
  - "add ioc"
  - "submit ioc"
  - "I found a new malicious repo"
  - "ioc-update"
---

# ioc-update

You are running the **clonesafe ioc-update** workflow. The user wants to contribute a new indicator of compromise to the clonesafe database. Your job is to gather the right information, validate it, produce a clean PR-ready diff, and (optionally) help them submit it.

## Hard rules

1. **Never add an IOC without a citable source.** Either a public report (CISA/FBI/Unit42/Snyk/Socket/Phylum/Mandiant/Microsoft/ESET) OR a clonesafe sample the user can attach. Hearsay is not acceptable.
2. **Never add IOCs based on nationality, name origin, or accent.** Those are discriminatory and ineffective.
3. **Never add a real person's name.** Use handles, email addresses, and domain-level identifiers only.
4. **Never add an identifier that is a legitimate brand.** If the attacker typosquatted a real project, the IOC should be the *typosquat* only, with a prominent note about which legitimate brand was impersonated. Better: use a pattern rule instead of naming the specific typosquat.
5. **Always anonymize victim data.** No real wallet addresses, no PESEL numbers, no real usernames, no personal emails from the victim's side.

## Workflow

### Step 1 — Identify the IOC type

Ask the user what kind of IOC they want to add:

- **Package** (npm, pypi, cargo, gem, composer, etc.) — goes to `iocs/packages.json`
- **Domain / IP** — goes to `iocs/domains.json`
- **GitHub org** — goes to `iocs/github-orgs.json` (only after verifying it's not a brand impersonation of a real project)
- **File hash (SHA256)** — goes to `iocs/hashes.json`
- **Pattern / regex** — goes to the pattern section of the relevant file
- **Recruiter handle** — goes to `iocs/recruiters.json` (reserved for `job-scam-detector`, not used by clonesafe itself)

### Step 2 — Gather required fields

For every IOC type, require:
- **Identifier** (the thing itself)
- **Type**
- **First seen** (date in ISO 8601, YYYY-MM-DD)
- **Campaign** (short slug — e.g., `contagious-interview-001`, `axios-compromise-2026`)
- **Source** (name of the publication / report / research org)
- **Source URL** (canonical link to the public report)
- **Description** (one paragraph: what it is, why it's an IOC, how it was used)
- **Confidence** (high / medium / low)

Type-specific additional fields:
- **Package**: list of affected versions
- **Domain**: resolved IPs (optional)
- **GitHub org**: list of related repos (optional)
- **Hash**: algorithm (default SHA256)

If the user can't provide a source URL, require them to attach a clonesafe sample under `samples/` that contains the evidence.

### Step 3 — Brand-impersonation check

Before adding any GitHub org or package name:

1. Search for the identifier on GitHub/npm registry/etc.
2. Compute Levenshtein distance to the top 10k packages / orgs
3. If distance ≤ 2 to a legitimate project, warn the user: "This looks like a typosquat of `<real project>`. Adding the typosquat to the IOC database risks harming the real project through search-result association. Consider instead adding a pattern rule like 'Levenshtein distance ≤ 2 from top-10k packages' which catches the typosquat without naming it."
4. If the user still wants to add it, require a very prominent note in the entry's `description` field that explicitly names the impersonated real project and states that the real project is not involved in any attack.

### Step 4 — Validate the entry

- JSON schema: match the format in `iocs/README.md`
- Alphabetical sort within the relevant file's `entries` array
- Unique `id` in the form `IOC-YYYY-NNN`
- No duplicate identifiers (check against existing entries)
- All required fields populated
- Source URL is a valid HTTPS link to a citable public source

### Step 5 — Produce the diff

Generate a patch-ready JSON diff. Show the user exactly what will be added:

```
iocs/packages.json:
@@ +12,8 @@
+      {
+        "id": "IOC-2026-042",
+        "identifier": "example-package",
+        "type": "package",
+        "versions": ["1.2.3"],
+        ...
+      }
```

### Step 6 — Submission

Ask the user how they want to submit:

1. **Open an issue on the clonesafe repo** — generate an issue body using the `ioc-submission.md` template, open `https://github.com/bkotrys/clonesafe/issues/new?template=ioc-submission.md&title=...` with pre-filled fields
2. **Open a PR directly** — if the user has forked the repo, guide them through creating a branch, applying the diff, committing, and pushing
3. **Just produce the patch file** — save to `data/pending-iocs/{timestamp}.patch` for the user to handle manually

### Step 7 — Encourage sample contribution

If the user's IOC came from a real attack on themselves or a friend, ask if they want to also contribute an **anonymized sample** to `samples/`. Samples are the highest-leverage contribution — they train the detection rules for everyone.

Walk them through:
- Creating `samples/{campaign-name}/README.md` with the anonymized story
- Extracting the malicious snippets (redact any PII)
- Writing the analysis / technical breakdown
- Submitting as part of the same PR as the IOC

## Validation checklist

Before producing the final diff, verify:

- [ ] Source is a citable public report OR attached clonesafe sample
- [ ] No real person's name in the entry
- [ ] No brand-impersonation risk (or prominently disclaimed)
- [ ] JSON syntax valid
- [ ] Schema fields all present
- [ ] Sort order maintained
- [ ] Unique `id` assigned
- [ ] Description explains what + why in one paragraph
- [ ] Confidence rating honest (don't inflate)

## Output

For a successful submission, show the user:
1. The exact diff
2. The URL they can visit to open the issue/PR
3. A brief thank-you and a note that they're helping other developers

For a failed submission (missing source, brand impersonation risk, etc.), explain what's missing and how to fix it. Don't add partial entries.

## Tone

- Collaborative, not gatekeep-y. The goal is to help contributors succeed, not reject them.
- But uphold the rules. A weak IOC is worse than none (false positives hurt the whole database).
- Celebrate good contributions. Thank the user specifically by name if they've contributed before.
