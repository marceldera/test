"""Editorial-integrity tests for the Global Threat Intelligence build."""
import copy
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tw import global_intel as G  # noqa: E402

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def base(**k):
    r = {
        "id": "GI-2026-0001", "record_type": "event", "publication_status": "published",
        "title": "Test event", "regions": ["Europe"], "countries": ["Testland"], "primary_category": "Cybersecurity",
        "priority": "MODERATE", "evidence_status": "Reported", "event_date": "2026-11-20",
        "published_at": "2026-11-20T10:00:00Z", "last_verified": "2026-11-22T10:00:00Z",
        "last_substantive_update": "2026-11-20T10:00:00Z", "trend": "Stable", "summary": "Summary.",
        "reported_claims": [{"text": "A claim.", "sources": [0], "attributed_to": "Someone"}],
        "impact_assessment": "Impact.", "priority_rationale": "Why.", "monitoring_actions": ["Watch."],
        "sources": [{"publisher": "Pub A", "title": "T", "published": "2026-11-20", "url": "https://a.example/1",
                     "type": "news", "accessed": "2026-11-21"}],
        "update_history": [{"date": "2026-11-20T10:00:00Z", "type": "published", "summary": "First published."}],
    }
    r.update(k)
    return r


class RecordRules(unittest.TestCase):
    def test_valid_record(self):
        self.assertEqual(G.validate_record(base())["id"], "GI-2026-0001")

    def test_high_needs_approval(self):
        with self.assertRaisesRegex(G.RecordError, "editorial approval"):
            G.validate_record(base(priority="HIGH"))
        G.validate_record(base(priority="HIGH", approved_by="Editor", approved_at="2026-11-21T10:00:00Z"))

    def test_draft_high_does_not_need_approval_yet(self):
        G.validate_record(base(priority="HIGH", publication_status="verification_pending"))

    def test_confirmed_needs_two_independent_sources(self):
        rec = base(evidence_status="Confirmed", approved_by="E", approved_at="2026-11-21T10:00:00Z",
                   confirmed_facts=[{"text": "Fact.", "sources": [0, 1]}])
        syndicated = dict(rec["sources"][0], publisher="Pub B", url="https://b.example/1", syndicated_from="Pub A")
        with self.assertRaisesRegex(G.RecordError, "independent"):
            G.validate_record(dict(rec, sources=rec["sources"] + [syndicated]))
        independent = dict(rec["sources"][0], publisher="Pub B", url="https://b.example/1")
        G.validate_record(dict(rec, sources=rec["sources"] + [independent]))

    def test_claims_must_cite_sources(self):
        with self.assertRaisesRegex(G.RecordError, "cite source"):
            G.validate_record(base(reported_claims=[{"text": "x", "sources": [5]}]))

    def test_rejects_unsafe_links_and_bad_enums(self):
        bad = base()
        bad["sources"][0]["url"] = "javascript:alert(1)"
        with self.assertRaisesRegex(G.RecordError, "https"):
            G.validate_record(bad)
        with self.assertRaisesRegex(G.RecordError, "priority"):
            G.validate_record(base(priority="SEVERE"))
        with self.assertRaisesRegex(G.RecordError, "regions"):
            G.validate_record(base(regions=["Mars"]))

    def test_demo_ids(self):
        with self.assertRaisesRegex(G.RecordError, "demonstration"):
            G.validate_record(base(demo=True))
        G.validate_record(base(id="GI-DEMO-2026-001", demo=True))

    def test_signal_keeps_observation_and_interpretation(self):
        with self.assertRaisesRegex(G.RecordError, "observed_action"):
            G.validate_record(base(record_type="signal"))
        G.validate_record(base(record_type="signal", observed_action="Guidance issued.", interpretation="Routine."))


class BuildRules(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.recs = self.root / "global-intelligence" / "editorial" / "records"
        self.recs.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root)

    def put(self, rec):
        (self.recs / f"{rec['id']}.json").write_text(json.dumps(rec))

    def test_build_outputs_and_drafts_hidden(self):
        self.put(base())
        self.put(base(id="GI-2026-0002", publication_status="verification_pending"))
        out, errs = G.build(self.root, NOW)
        self.assertEqual(errs, [])
        self.assertEqual([r["id"] for r in out["active-threats.json"]["records"]], ["GI-2026-0001"])
        self.assertEqual(out["last-updated.json"]["pending_review"], 1)
        self.assertEqual(out["executive-summary.json"]["counts"]["active"], 1)
        self.assertTrue((self.root / "global-intelligence" / "data" / "last-updated.json").exists())

    def test_history_is_append_only(self):
        rec = base()
        self.put(rec)
        self.assertEqual(G.build(self.root, NOW)[1], [])
        edited = copy.deepcopy(rec)
        edited["update_history"][0]["summary"] = "Rewritten."
        self.put(edited)
        _, errs = G.build(self.root, NOW)
        self.assertTrue(any("changed or removed" in e for e in errs))
        # priority change without a history entry is blocked; with one it passes
        changed = copy.deepcopy(rec)
        changed.update(priority="LOW")
        self.put(changed)
        self.assertTrue(any("without a new update_history" in e for e in G.build(self.root, NOW)[1]))
        changed["update_history"].append({"date": "2026-11-22T10:00:00Z", "type": "priority", "summary": "Lowered."})
        changed["last_substantive_update"] = "2026-11-22T10:00:00Z"
        self.put(changed)
        self.assertEqual(G.build(self.root, NOW)[1], [])

    def test_published_record_cannot_vanish(self):
        self.put(base())
        G.build(self.root, NOW)
        (self.recs / "GI-2026-0001.json").unlink()
        self.assertTrue(any("removed" in e for e in G.build(self.root, NOW)[1]))

    def test_demo_and_live_never_mix(self):
        self.put(base())
        self.put(base(id="GI-DEMO-2026-001", demo=True))
        self.assertTrue(any("demonstration" in e for e in G.build(self.root, NOW)[1]))

    def test_resolved_goes_to_history(self):
        rec = base(trend="Resolved")
        rec["update_history"].append({"date": "2026-11-21T10:00:00Z", "type": "resolved", "summary": "Resolved."})
        self.put(rec)
        out, errs = G.build(self.root, NOW)
        self.assertEqual(errs, [])
        self.assertEqual(len(out["historical-threats.json"]["records"]), 1)
        self.assertEqual(out["active-threats.json"]["records"], [])

    def test_repository_records_build(self):
        _, errs = G.build(ROOT, NOW, write=False)
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
