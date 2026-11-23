"""Threat Map graph built from a tiny ATT&CK-shaped bundle."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tw.relationships import build_graph  # noqa: E402
from tw.validate import validate_relationships  # noqa: E402


def ref(eid, kind):
    return [{"source_name": "mitre-attack", "external_id": eid, "url": f"https://attack.mitre.org/{kind}/{eid}"}]


BUNDLE = {"objects": [
    {"type": "campaign", "id": "campaign--1", "name": "Test Campaign", "external_references": ref("C9999", "campaigns"),
     "description": "Actors exploited CVE-2099-0001 in edge devices.", "first_seen": "2025-01-01T00:00:00Z",
     "last_seen": "2025-06-01T00:00:00Z", "modified": "2026-04-01T00:00:00Z"},
    {"type": "campaign", "id": "campaign--2", "name": "No CVE Campaign", "external_references": ref("C9998", "campaigns"),
     "description": "Nothing here.", "modified": "2026-04-01T00:00:00Z"},
    {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Test Group", "aliases": ["Test Group", "TG"],
     "external_references": ref("G9999", "groups")},
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Exploit Public-Facing Application",
     "external_references": ref("T1190", "techniques")},
    {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Phishing", "external_references": ref("T1566", "techniques")},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "attributed-to", "source_ref": "campaign--1",
     "target_ref": "intrusion-set--1", "modified": "2026-04-02T00:00:00Z",
     "external_references": [{"source_name": "Vendor 2025", "url": "https://example.com/report"}]},
    {"type": "relationship", "id": "relationship--2", "relationship_type": "uses", "source_ref": "campaign--1",
     "target_ref": "attack-pattern--1", "modified": "2026-04-02T00:00:00Z"},
    {"type": "relationship", "id": "relationship--3", "relationship_type": "uses", "source_ref": "campaign--1",
     "target_ref": "attack-pattern--2", "modified": "2026-04-02T00:00:00Z"},
]}


class GraphTests(unittest.TestCase):
    def test_graph(self):
        g = build_graph(BUNDLE, {"CVE-2099-0001": {"product": "Example Gateway", "kev": True, "cvss": 9.8}}, "20.1",
                        "2026-11-23T00:00:00Z")
        self.assertEqual(validate_relationships(g), [])
        self.assertEqual(g["dataset"]["status"], "verified")
        labels = {n["label"] for n in g["nodes"]}
        self.assertIn("Test Group", labels)
        self.assertNotIn("No CVE Campaign", labels)                 # campaigns without a named CVE are skipped
        self.assertNotIn("T1566 Phishing", labels)                  # only exploitation techniques
        rel = {(e["relation"], e["evidence"]["url"]) for e in g["edges"]}
        self.assertIn(("attributed", "https://example.com/report"), rel)      # cites the report when ATT&CK has one
        self.assertIn(("exploits", "https://attack.mitre.org/campaigns/C9999"), rel)
        cve = next(n for n in g["nodes"] if n["type"] == "cve")
        self.assertTrue(cve["kev"])


if __name__ == "__main__":
    unittest.main()
