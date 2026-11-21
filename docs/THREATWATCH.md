# Aegis ThreatWatch — operations runbook

Free, public cyber threat intelligence at `https://aegisdefensecyber.com/threatwatch/`.
Spec: *Aegis ThreatWatch Complete Project Blueprint* (21 Nov 2026).

## What is built (Phases A–D)

| Area | Status |
|---|---|
| Homepage “Threat Intelligence” link (desktop nav, mobile nav, footer) | Done |
| `/threatwatch/` daily brief — all 9 editorial sections, freshness/stale flag, CVE details | Done |
| Monthly summary — 4 reconciled metrics, collapsible chronology, 6-month archive | Done |
| `/threatwatch/map.html` relationship explorer — filters, keyboard, details, table fallback | Done, **demo data** |
| Publisher: CISA KEV + FIRST EPSS + NVD enrichment, prioritisation, quality gate | Done |
| ET-aware schedule, idempotent, last-good-edition retained on failure | Done |
| Email subscription (Phase E) | **Not started** — signup hidden until `subscription-config.json` is enabled |
| `/threatwatch/validate.html` Vulnerability Validation — Phase 1 (public CVE lookup + guidance) | Done |
| Vulnerability Validation — Phase 2 (authorized active scanning) | **Not built** — needs separate secured backend, legal/ROE approval |

## Files

```
index.html                              homepage (3 lines added)
threatwatch/index.html, map.html        public pages
threatwatch/assets/                     CSS + JS (no third-party JS)
threatwatch/subscription-config.json    public signup URL only — never secrets
threatwatch/data/relationships.json     graph data (status: demo | verified)
threatwatch/data/editorial/YYYY-MM-DD.json  optional reviewed analyst overlay
threatwatch/data/{latest,status,state}.json, briefs/, monthly/   generated — do not hand-edit
scripts/build_brief.py                  publisher entry point
scripts/tw/                             sources, brief composition, validation
scripts/validate_data.py                CI gate for committed data
tests/test_publisher.py                 offline tests (synthetic CVE-2099 fixtures)
.github/workflows/publish-threatwatch.yml
```

## First deployment

1. Create branch `threatwatch`, add these files, open a PR. CI runs the tests.
2. Repo **Settings → Actions → General → Workflow permissions**: allow *Read and write*.
   If `main` is protected, allow `github-actions[bot]` to push or switch publishing to a PR-based flow.
3. Optional: add secret `NVD_API_KEY` (free from NVD) — raises the rate limit from 5 to 50 req/30 s.
4. Pin `actions/checkout` and `actions/setup-python` to commit SHAs (TODO in workflow).
5. Merge. Then **Actions → Publish ThreatWatch → Run workflow** with *force = true* to create the first edition.
   Until that run succeeds, `/threatwatch/` shows a clear “temporarily unavailable” message.
6. Verify: HTTPS, CNAME still `aegisdefensecyber.com`, homepage ↔ ThreatWatch links on phone and desktop.
   Confirm the bot’s data commit triggered the *pages-build-deployment* run.

## Daily schedule

Cron fires 10:50 and 11:50 UTC (+ 13:35, 15:35 retries). The publisher publishes once per
America/New_York day, never before 06:45 ET. Expect ~06:50–07:30 ET; GitHub cron is best-effort,
so treat 07:00 ET as a target, not an SLA.

## Adding analyst intelligence (campaigns, actors, industries)

Automated feeds never infer actors or sectors from KEV. To publish those sections, commit
`threatwatch/data/editorial/<ET date>.json` **before** the run (or re-run with force):

```json
{
  "reviewedBy": "M. Dera",
  "reviewedAt": "2026-11-22T11:30:00Z",
  "summary": "Optional replacement executive paragraph.",
  "campaigns":  [{"name": "...", "summary": "...", "cves": ["CVE-..."], "techniques": ["T1190"],
                  "confidence": "high", "sources": ["https://..."]}],
  "industries": [{"name": "Healthcare", "relation": "observed_targeting", "regions": ["North America"],
                  "confidence": "moderate", "sources": ["https://..."]}],
  "actors":     [{"name": "...", "aliases": [], "type": "state-linked", "motivation": "...",
                  "sectors": [], "cves": [], "confidence": "moderate", "sources": ["https://..."]}],
  "sources":    [{"name": "Vendor report title", "url": "https://..."}]
}
```

Every item needs `confidence` (high|moderate|low) and at least one https source, or the run is blocked.
This is where a ChatGPT/Claude morning analysis can feed in: generate a draft, check it against its sources, commit it.

## Replacing demo map data

Edit `threatwatch/data/relationships.json`, set `dataset.status` to `"verified"`. Allowed edges:
actor→campaign, campaign→cve/industry/geography/technique, actor→technique. Verified edges need
`evidence.url` and `evidence.reportDate`. `python scripts/validate_data.py` must pass.

## Vulnerability Validation (addendum v1.0, Phase 1)

Public, read-only CVE lookup. It never scans and has no scan button. Phase 2 (authorized assessments) is deliberately absent: GitHub Pages can't safely run scans or hold customer data.

**Coverage:** every CISA KEV CVE, CVEs with CVSS ≥ 7.0 published in the last 120 days (`TW_RETAIN_DAYS`), and every CVE featured in a brief. Unknown CVEs show a "not in catalog" page linking to NVD and CVE.org.

**Pipeline** (`scripts/build_catalog.py`, runs after each published edition):

1. CISA KEV (required — failure blocks the catalog run).
2. NVD incremental sync by `lastModified` window from the cursor in `data/cves/state.json`. The first run backfills 30 days (`TW_NVD_BACKFILL_DAYS`). If NVD fails, cached records are kept and a warning is shown.
3. Per-CVE NVD lookups for KEV CVEs not yet enriched: 40 per run without a key, 400 with `NVD_API_KEY`. The backlog clears over a few runs. Records awaiting NVD show "NVD details not yet collected".
4. EPSS for every catalog CVE, stored in one file, `data/cves/epss.json`. A missing score shows as Unknown, never 0.
5. Nuclei template **metadata** indexed from a sparse checkout of `projectdiscovery/nuclei-templates`. Nothing is executed. The commit is recorded in `data/cves/status.json`.
6. Quality gate (schema, https-only links, review file) → write changed records only, prune CVEs that fell out of coverage.

**Curating checks:** add entries to `threatwatch/data/validation/reviews.json`, then run the workflow with force.

```json
{"entries": [
  {"cve": "CVE-2024-3400", "method": "nuclei", "path": "http/cves/2024/CVE-2024-3400.yaml",
   "reviewStatus": "reviewed", "invasiveness": "intrusive", "lastReviewed": "2026-11-21",
   "reviewer": "M. Dera", "note": "Uses OAST callback; run only in an approved window."},
  {"cve": "CVE-2024-3400", "method": "authenticated-check", "name": "Check PAN-OS version in the admin console",
   "reviewStatus": "reviewed", "invasiveness": "passive", "lastReviewed": "2026-11-21", "reviewer": "M. Dera",
   "url": "https://security.paloaltonetworks.com/CVE-2024-3400"}
]}
```

`method`: nuclei | nmap-nse | vendor-script | config-check | authenticated-check | manual.
`reviewStatus`: reviewed | unreviewed | rejected (a rejected entry stays visible, marked "Rejected by Aegis").
`invasiveness`: passive | safe-probe | intrusive. A bad entry blocks the run, and the last good catalog stays live.

**Priority rubric** (client-side; the visitor's choices never leave the browser):

| Tier | Rule |
|---|---|
| 1 Immediate | KEV-listed and not internal-only; or CVSS ≥ 9 + exploit reference + internet-facing |
| 2 High | KEV-listed (internal); EPSS ≥ 95th percentile; or CVSS ≥ 9 + internet-facing |
| 3 Planned | CVSS ≥ 7 |
| 4 Monitor | Everything else, including unscored |

High asset criticality raises one tier. Low criticality lowers one tier (never for KEV). "Not deployed" means not applicable.

**Controlled test plan** (`validate.html#plan`): visitors pick 1–25 CVEs and the page builds a Nuclei command locked to those templates with `-id`. Defaults: `-etags intrusive,dos,fuzz`, `-ni` (no out-of-band callbacks), `-rl 10 -c 5 -timeout 10`, JSONL output. The visitor must tick four authorization statements and enter a name before any command appears. Targets are checked against a strict hostname/IP/URL pattern and shell-quoted. Everything happens in the browser: only the selected CVE IDs persist (localStorage), never targets or attestations. Aegis runs nothing and receives nothing. A downloadable JSON record captures scope, options, attestations and the template commit for the tester's audit trail. Flags verified against `projectdiscovery/nuclei` `cmd/nuclei/main.go` on 21 Nov 2026.

**Disclaimer** (`validate.html#disclaimer`): authorized use only (CFAA), no scanning by Aegis, operational risk, results are signals, third-party templates, no warranty. Have counsel review it before the live launch.

**Badges:** KEV-listed · High EPSS (≥ 95th percentile) · Critical CVSS (≥ 9.0) · Public exploit reported (NVD reference tagged *Exploit*) · Vendor fix/mitigation (NVD reference tagged *Patch* or *Mitigation*). Each is shown separately; none is treated as proof of another.

## Failure handling

- Feed down, schema change, >5% malformed KEV rows, or any quality-gate error → nothing is published,
  `status.json` records the error, the page keeps the last good edition, the workflow run turns red.
- Edition older than 30 h → page shows a **Stale** badge.
- Rollback: `git revert` the bot commit; the previous `latest.json` comes back.
- Corrections: edit the editorial file and re-run with *force*, or revert.

## Phase E — email (not built)

Blocked on choosing a bulk-mail provider (Zoho Mail is a mailbox, not a campaign platform; Zoho Campaigns
is an option). Required: hosted double-opt-in form, SPF/DKIM/DMARC without breaking Zoho Mail DNS,
physical mailing address and unsubscribe in every email, suppression list. When ready, set
`subscription-config.json` → `{"enabled": true, "signupUrl": "https://..."}` and wire the commented
*Send digest* step (runs only when `published == 'true'`).

## Local testing

```
python -m unittest discover -s tests -v
python scripts/validate_data.py
python -m http.server 8000   # then open http://localhost:8000/threatwatch/
```
