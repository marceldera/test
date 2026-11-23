# AEGIS Global Threat Intelligence — editorial runbook

Public pages: `global-intelligence/index.html` (dashboard) and `global-intelligence/assessment.html?id=…`.
Spec: *AEGIS Global Threat Intelligence Dashboard — Feature Development Specification v1.0* (Phases 1–2 built).

## How data flows
`global-intelligence/editorial/records/<ID>.json` (one file per event, edited by analysts)
→ `python scripts/build_global.py` (validates every editorial rule; any error blocks the build and leaves
the published data unchanged)
→ `global-intelligence/data/*.json` (generated; never edit by hand) → static dashboard.

The workflow `.github/workflows/global-intelligence.yml` runs the build daily at 7:00 AM ET and whenever a
record changes. The dashboard says "not real-time" and shows collection time vs. last editorial verification.

## Workflow states (`publication_status`)
`collected → analyzed → verification_pending → approved → published → updated → archived`.
Only `published`, `updated` and `archived` appear publicly. Drafts never do.

## Rules the build enforces
- Required fields per spec §11; enums for region, category, priority, evidence, trend, source type.
- Every claim (`confirmed_facts`, `reported_claims`, `international_perspectives`) cites source numbers.
- **Confirmed** evidence needs ≥ 2 independent sources. Mark republished copies with `syndicated_from`; they
  count once. **Critical/High** priority or **Confirmed** evidence needs `approved_by` + `approved_at`.
- Signals (`record_type: "signal"`) need `observed_action` and `interpretation`, shown separately.
- `update_history` is append-only. A change to priority, evidence status or trend needs a new history entry
  (`priority`, `evidence_status`, `trend`, `correction` or `resolved`). `published_at` never changes.
  A published record can't be deleted. Set `publication_status: "archived"` instead.
- Links must be https. All text is rendered as plain text (no HTML).
- Demonstration records (`GI-DEMO-…`, `demo: true`) can never be published alongside live records.

## Going live
1. Write the first real records as `GI-2026-0001.json` etc. (copy a demo file for the structure).
2. Set every demo record's `publication_status` to `archived`, or delete the demo files *before* the first live
   build (demo records may be removed; live ones may not).
3. Run `python scripts/build_global.py` and commit both the records and `global-intelligence/data/`.

## Phases not built yet (spec §12)
3 Collection (source registry, feeds, scheduled ingestion, dedup, independence checks) · 4 Verification
(claim extraction, preliminary priorities, approval queue) · 5 World map / timeline charts · 6 email digest.
Collected material must be treated as untrusted input, including when passed to AI agents.
