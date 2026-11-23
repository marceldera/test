"""Offline tests for the ThreatWatch publisher.

Fixtures are synthetic (CVE-2099-*, vendor "ExampleCorp") and never published.
Run:  python -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_brief.py"
sys.path.insert(0, str(ROOT / "scripts"))

from tw.validate import validate_relationships  # noqa: E402


def kev_record(n, added, ransomware="Unknown", vendor="ExampleCorp", product="Gateway"):
    return {"cveID": f"CVE-2099-{n:04d}", "vendorProject": vendor, "product": product,
            "vulnerabilityName": f"{vendor} {product} Test Vulnerability {n}", "dateAdded": added,
            "shortDescription": "Synthetic test record.", "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2099-12-31", "knownRansomwareCampaignUse": ransomware,
            "notes": "https://example.com/advisory ; javascript:alert(1)", "cwes": ["CWE-78"]}


def nvd(cid, score, av="NETWORK", pr="NONE", sev="CRITICAL"):
    return {"vulnerabilities": [{"cve": {
        "id": cid, "vulnStatus": "Analyzed", "published": "2099-01-01T00:00:00",
        "descriptions": [{"lang": "en", "value": "Synthetic."}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov", "cvssData": {
            "baseScore": score, "baseSeverity": sev, "vectorString": "CVSS:3.1/AV:N",
            "attackVector": av, "privilegesRequired": pr, "userInteraction": "NONE"}}]},
        "references": [{"url": "https://example.com/vendor", "tags": ["Vendor Advisory"]},
                       {"url": "http://insecure.example.com", "tags": ["Patch"]}]}}]}


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Path(self.tmp.name) / "fx"
        self.data = Path(self.tmp.name) / "data"
        self.fx.mkdir()
        records = [kev_record(1, "2026-11-20"), kev_record(2, "2026-11-21", "Known", "OtherCo", "VPN"),
                   kev_record(3, "2026-11-21", product="Agent"), kev_record(4, "2026-11-02"),
                   kev_record(5, "2026-10-15", "Known"),
                   {"cveID": "NOT-A-CVE", "vendorProject": "x", "product": "y",
                    "vulnerabilityName": "z", "dateAdded": "2026-11-21"}]
        self.write("kev.json", {"catalogVersion": "2099.01.01", "dateReleased": "2026-11-21T15:00:00Z",
                                "count": len(records), "vulnerabilities": records})
        self.write("epss.json", {"status": "OK", "data": [
            {"cve": "CVE-2099-0001", "epss": "0.94", "percentile": "0.998", "date": "2026-11-21"},
            {"cve": "CVE-2099-0004", "epss": "0.12", "percentile": "0.93", "date": "2026-11-21"}]})
        self.write("nvd-CVE-2099-0001.json", nvd("CVE-2099-0001", 9.8))
        self.write("nvd-CVE-2099-0002.json", nvd("CVE-2099-0002", 7.5, pr="LOW", sev="HIGH"))
        self.write("nvd-CVE-2099-0003.json", nvd("CVE-2099-0003", 7.8, av="LOCAL", pr="LOW", sev="HIGH"))

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, obj):
        (self.fx / name).write_text(json.dumps(obj))

    def run_pub(self, now, *extra, fixtures=True):
        env = {**os.environ, "TW_DATA_DIR": str(self.data), "TW_NOW": now, "TW_SKIP_CATALOG": "1"}
        if fixtures:
            env["TW_FIXTURES"] = str(self.fx)
        return subprocess.run([sys.executable, str(SCRIPT), *extra], env=env, capture_output=True, text=True)

    def load(self, rel):
        return json.loads((self.data / rel).read_text())

    def test_first_edition(self):
        r = self.run_pub("2026-11-21T12:10:00+00:00")
        self.assertEqual(r.returncode, 0, r.stderr)
        b = self.load("latest.json")
        self.assertEqual(b["edition"], "2026-11-21")
        self.assertEqual([c["cve"] for c in b["cves"]], ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"])
        pr = {c["cve"]: c["priority"] for c in b["cves"]}
        self.assertEqual(pr, {"CVE-2099-0001": "emergency", "CVE-2099-0002": "emergency",
                              "CVE-2099-0003": "routine"})
        self.assertEqual(len(b["actions"]), 2)  # never padded to five
        urls = [s["url"] for c in b["cves"] for s in c["sources"]]
        self.assertTrue(all(u.startswith("https://") for u in urls))
        self.assertNotIn("javascript:alert(1)", json.dumps(b))
        self.assertEqual(b["actors"]["status"], "not_covered")
        self.assertIn("Exploit maturity", b["coverage"]["unknownFields"])
        m = self.load("monthly/2026-11.json")
        self.assertEqual({x["id"]: x["value"] for x in m["metrics"]},
                         {"kev_added": 4, "vendors": 2, "ransomware": 1, "epss90": 2})

    def test_gate_and_idempotency(self):
        early = self.run_pub("2026-11-21T10:50:00+00:00")  # 05:50 EST
        self.assertIn("before publication time", early.stdout)
        self.assertFalse((self.data / "latest.json").exists())
        self.assertEqual(self.run_pub("2026-11-21T11:50:00+00:00").returncode, 0)
        again = self.run_pub("2026-11-21T13:30:00+00:00")
        self.assertIn("already published", again.stdout)

    def test_next_day_diff_and_no_new(self):
        self.run_pub("2026-11-21T12:10:00+00:00")
        r = self.run_pub("2026-11-22T12:10:00+00:00")
        self.assertEqual(r.returncode, 0, r.stderr)
        b = self.load("latest.json")
        self.assertEqual(b["cves"], [])
        self.assertIn("does not mean no new threats", b["executive"]["summary"])
        idx = self.load("briefs/index.json")
        self.assertEqual([e["edition"] for e in idx["editions"]], ["2026-11-22", "2026-11-21"])

    def test_ransomware_flag_change(self):
        self.run_pub("2026-11-21T12:10:00+00:00")
        kev = json.loads((self.fx / "kev.json").read_text())
        kev["vulnerabilities"][3]["knownRansomwareCampaignUse"] = "Known"
        self.write("kev.json", kev)
        self.run_pub("2026-11-22T12:10:00+00:00")
        types = [c["type"] for c in self.load("latest.json")["changes"]]
        self.assertIn("ransomware_flag", types)

    def test_failure_keeps_last_good(self):
        self.run_pub("2026-11-21T12:10:00+00:00")
        before = (self.data / "latest.json").read_text()
        self.write("kev.json", {"unexpected": True})
        r = self.run_pub("2026-11-22T12:10:00+00:00")
        self.assertEqual(r.returncode, 1)
        self.assertEqual((self.data / "latest.json").read_text(), before)
        self.assertFalse(self.load("status.json")["ok"])

    def test_editorial_requires_sources(self):
        ed = self.data / "editorial"
        ed.mkdir(parents=True)
        (ed / "2026-11-21.json").write_text(json.dumps({
            "reviewedBy": "M. Dera", "reviewedAt": "2026-11-21T11:30:00Z",
            "actors": [{"name": "Example Actor", "confidence": "high", "sources": []}]}))
        r = self.run_pub("2026-11-21T12:10:00+00:00")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no https source", r.stderr)


class BriefBuildsCatalogTest(PublisherTests):
    def test_catalog_built_after_publish(self):
        env = {**os.environ, "TW_DATA_DIR": str(self.data), "TW_NOW": "2026-11-21T12:10:00+00:00",
               "TW_FIXTURES": str(self.fx)}
        (self.fx / "nvd-bulk-0.json").write_text(json.dumps({"totalResults": 0, "vulnerabilities": []}))
        r = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        idx = json.loads((self.data / "cves" / "index.json").read_text())
        ids = {row[0] for row in idx["items"]}
        self.assertTrue({"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"} <= ids)
        rec = json.loads((self.data / "cves" / "2099" / "CVE-2099-0001.json").read_text())
        self.assertEqual(rec["cvss"]["score"], 9.8)  # per-CVE NVD lookup for a brief CVE
        self.assertEqual(rec["appearsIn"]["briefs"], ["2026-11-21"])


class RelationshipTests(unittest.TestCase):
    def test_shipped_dataset_valid(self):
        g = json.loads((ROOT / "threatwatch" / "data" / "relationships.json").read_text())
        self.assertEqual(validate_relationships(g), [])
        self.assertEqual(g["dataset"]["status"], "verified")
        self.assertFalse([n for n in g["nodes"] if "2099" in n.get("label", "")])

    def test_direct_actor_cve_edge_rejected(self):
        g = {"dataset": {"status": "verified"},
             "nodes": [{"id": "a", "type": "actor"}, {"id": "c", "type": "cve", "label": "CVE-2099-0001"}],
             "edges": [{"id": "e", "source": "a", "target": "c", "confidence": "high", "relation": "exploits"}]}
        errs = validate_relationships(g)
        self.assertTrue(any("not allowed" in e for e in errs))
        self.assertTrue(any("evidence" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
