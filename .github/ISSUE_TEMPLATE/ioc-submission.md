---
name: IOC submission
about: Report a malicious repo, package, domain, or GitHub org for inclusion in the clonesafe database
title: "iocs: [describe what you found]"
labels: ioc-submission
---

## What did you find?

<!-- One-paragraph summary of the malicious artifact -->

## Artifact type

- [ ] Malicious GitHub repo (URL + commit SHA)
- [ ] Malicious npm package (name + version)
- [ ] Exfil / C2 domain
- [ ] Scam GitHub org
- [ ] Other: ___

## Details

**Repo / package / domain:**
```
<paste here>
```

**First seen (date):**
<!-- YYYY-MM-DD -->

**Source of discovery:**
<!-- Your own research? A public report? Threat feed? -->

## Indicators

**Lifecycle scripts / code snippets** (anonymize any PII):
```js
<paste the smoking gun>
```

**Exfil endpoints / domains observed:**
- `example[.]com`

**Related IOCs (packages, domains, orgs from the same campaign):**
- 

## What clonesafe currently says

<!-- Did you run `vet-repo` on this? What was the verdict? -->
<!-- If it caught it: which rule? If it missed it: what should we add? -->

## Should this be a sample in `samples/`?

- [ ] Yes, I can submit an anonymized sample via PR
- [ ] I've attached the relevant snippets above for someone else to package
- [ ] This is too sensitive to publish publicly — private disclosure preferred

## Consent

- [ ] I confirm this submission contains no real victim PII
- [ ] I confirm I have the right to share these artifacts publicly
