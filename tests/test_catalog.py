"""Offline tests for the Vulnerability Validation catalog (synthetic CVE-2099 data)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_catalog.py"
NOW = "2026-11-21T12:30:00+00:00"


def nvd_rec(cid, score, published="2026-11-01T10:00:00.000", exploit=False, patch=True):
    refs = [{"url": "https://example.com/advisory", "tags": ["Vendor Advisory"] + (["Patch"] if patch else [])},
            {"url": "javascript:alert(1)", "tags": ["Exploit"]}]
    if exploit:
        refs.append({"url": "https://example.com/poc", "tags": ["Exploit", "Third Party Advisory"]})
    metrics = {} if score is None else {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov", "cvssData": {
        "baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK",
        "privilegesRequired": "NONE", "userInteraction": "NONE"}}]}
    return {"id": cid, "published": published, "lastModified": "2026-11-20T08:00:00.000", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": f"Synthetic {cid}."}], "metrics": metrics,
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:examplecorp:gateway:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.0", "versionEndExcluding": "1.4.2"},
                {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
            "references": refs}


def kev(cid, added):
    return {"cveID": cid, "vendorProject": "ExampleCorp", "product": "Gateway", "vulnerabilityName": f"{cid} test",
            "dateAdded": added, "shortDescription": "Synthetic.", "requiredAction": "Apply updates.",
            "dueDate": "2099-12-31", "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []}


TEMPLATE = """id: {cid}

info:
  name: ExampleCorp Gateway - Test
  author: test
  severity: critical
  classification:
    cve-id: {cid}
  metadata:
    verified: {verified}
  tags: cve,{extra}examplecorp
"""


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.fx, self.data, self.nuc = t / "fx", t / "data", t / "nuclei"
        for d in (self.fx, self.data / "validation", self.data / "briefs", self.nuc / "http/cves/2099"):
            d.mkdir(parents=True)
        self.w("kev.json", {"catalogVersion": "2099.1", "vulnerabilities": [kev("CVE-2099-0001", "2026-11-20"),
                                                                            kev("CVE-2099-0002", "2024-01-10")]})
        self.w("nvd-bulk-0.json", {"totalResults": 4, "vulnerabilities": [
            {"cve": nvd_rec("CVE-2099-0001", 9.8)},
            {"cve": nvd_rec("CVE-2099-0010", 9.1, exploit=True)},          # recent critical, kept
            {"cve": nvd_rec("CVE-2099-0011", 5.3)},                        # medium, recent: kept (90-day scope)
            {"cve": nvd_rec("CVE-2099-0012", 8.8, published="2025-01-01T00:00:00.000")}]})  # old, dropped
        self.w("nvd-CVE-2099-0002.json", {"vulnerabilities": [{"cve": nvd_rec("CVE-2099-0002", None, patch=False)}]})
        self.w("epss.json", {"data": [{"cve": "CVE-2099-0001", "epss": "0.91", "percentile": "0.99", "date": "2026-11-21"}]})
        (self.nuc / "http/cves/2099/CVE-2099-0001.yaml").write_text(TEMPLATE.format(cid="CVE-2099-0001", verified="true", extra="intrusive,oast,"))
        (self.nuc / "http/cves/2099/CVE-2099-0010.yaml").write_text(TEMPLATE.format(cid="CVE-2099-0010", verified="false", extra=""))
        (self.data / "briefs" / "2026-11-21.json").write_text(json.dumps({"cves": [{"cve": "CVE-2099-0001"}]}))

    def tearDown(self):
        self.tmp.cleanup()

    def w(self, name, obj):
        (self.fx / name).write_text(json.dumps(obj))

    def run_cat(self, nuclei=True, **env):
        e = {**os.environ, "TW_DATA_DIR": str(self.data), "TW_FIXTURES": str(self.fx), "TW_NOW": NOW, **env}
        if nuclei:
            e.update(TW_NUCLEI_DIR=str(self.nuc), TW_NUCLEI_COMMIT="abc1234")
        return subprocess.run([sys.executable, str(SCRIPT)], env=e, capture_output=True, text=True)

    def rec(self, cid):
        return json.loads((self.data / "cves" / cid.split("-")[1] / f"{cid}.json").read_text())

    def test_build(self):
        r = self.run_cat()
        self.assertEqual(r.returncode, 0, r.stderr)
        idx = json.loads((self.data / "cves" / "index.json").read_text())
        ids = sorted(row[0] for row in idx["items"])
        self.assertEqual(ids, ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0010", "CVE-2099-0011"])
        a = self.rec("CVE-2099-0001")
        self.assertTrue(a["exploitStatus"]["kevListed"])
        self.assertFalse(a["exploitStatus"]["publicExploitReference"])  # javascript: ref discarded
        self.assertEqual(a["affected"], [{"vendor": "examplecorp", "product": "gateway", "versions": ">= 1.0, < 1.4.2", "part": "a"}])
        d = a["detections"][0]
        self.assertEqual((d["invasiveness"], d["outOfBand"], d["upstreamVerified"], d["reviewStatus"]),
                         ("intrusive", True, True, "unreviewed"))
        self.assertIn("/blob/main/http/cves/2099/", d["url"])
        st0 = json.loads((self.data / "cves" / "status.json").read_text())
        self.assertEqual(st0["sources"]["nucleiCommit"], "abc1234")
        self.assertEqual(a["appearsIn"]["briefs"], ["2026-11-21"])
        b = self.rec("CVE-2099-0010")
        self.assertTrue(b["exploitStatus"]["publicExploitReference"])
        self.assertIsNone(b["kev"])
        self.assertEqual(self.rec("CVE-2099-0002")["cvss"], None)  # NVD has no score: stays null
        epss = json.loads((self.data / "cves" / "epss.json").read_text())
        self.assertNotIn("CVE-2099-0010", epss["scores"])  # missing EPSS is absent, never 0
        st = json.loads((self.data / "cves" / "status.json").read_text())
        self.assertTrue(st["ok"])

    def test_cached_index_and_reviews(self):
        self.assertEqual(self.run_cat().returncode, 0)
        (self.data / "validation" / "reviews.json").write_text(json.dumps({"entries": [
            {"cve": "CVE-2099-0010", "method": "nuclei", "path": "http/cves/2099/CVE-2099-0010.yaml",
             "reviewStatus": "reviewed", "invasiveness": "safe-probe", "lastReviewed": "2026-11-21",
             "reviewer": "Aegis", "note": "Version check only."},
            {"cve": "CVE-2099-0001", "method": "authenticated-check", "name": "Check installed package version",
             "reviewStatus": "reviewed", "invasiveness": "passive", "lastReviewed": "2026-11-21", "reviewer": "Aegis"}]}))
        r = self.run_cat(nuclei=False)  # no checkout: cached index reused
        self.assertEqual(r.returncode, 0, r.stderr)
        b = self.rec("CVE-2099-0010")["detections"][0]
        self.assertEqual((b["reviewStatus"], b["lastReviewed"]), ("reviewed", "2026-11-21"))
        a = self.rec("CVE-2099-0001")["detections"]
        self.assertEqual(a[0]["method"], "authenticated-check")  # reviewed sorts first

    def test_bad_review_blocks(self):
        self.assertEqual(self.run_cat().returncode, 0)
        before = (self.data / "cves" / "index.json").read_text()
        (self.data / "validation" / "reviews.json").write_text(json.dumps({"entries": [
            {"cve": "CVE-2099-0001", "method": "exploit-kit", "reviewStatus": "reviewed", "invasiveness": "passive",
             "lastReviewed": "2026-11-21", "reviewer": "x"}]}))
        r = self.run_cat()
        self.assertEqual(r.returncode, 1)
        self.assertIn("method must be one of", r.stderr)
        self.assertEqual((self.data / "cves" / "index.json").read_text(), before)

    def test_kev_failure_keeps_last_good(self):
        self.assertEqual(self.run_cat().returncode, 0)
        before = (self.data / "cves" / "index.json").read_text()
        self.w("kev.json", {"broken": True})
        self.assertEqual(self.run_cat().returncode, 1)
        self.assertEqual((self.data / "cves" / "index.json").read_text(), before)

    def test_nvd_outage_is_warning(self):
        self.assertEqual(self.run_cat().returncode, 0)
        (self.fx / "nvd-bulk-0.json").unlink()
        r = self.run_cat()
        self.assertEqual(r.returncode, 0, r.stderr)
        st = json.loads((self.data / "cves" / "status.json").read_text())
        self.assertTrue(any("NVD sync failed" in w for w in st["warnings"]))
        self.assertTrue((self.data / "cves" / "2099" / "CVE-2099-0010.json").exists())  # cache kept


NSE = """description = [[Checks for CVE.]]
categories = {"vuln", "safe"}
action = function(host, port)
  local vuln = { IDS = {CVE = 'CVE-2099-0010'} }
end
"""


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT / "scripts"))

    def test_nmap_index(self):
        from tw.detections import index_nmap
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "scripts"
            d.mkdir()
            (d / "http-vuln-cve2099-0011.nse").write_text('categories = {"vuln", "intrusive"}\n')
            (d / "example-check.nse").write_text(NSE)
            (d / "unrelated.nse").write_text('categories = {"safe"}\n')
            idx = index_nmap(Path(t))
        self.assertEqual(sorted(idx), ["CVE-2099-0010", "CVE-2099-0011"])
        self.assertEqual(idx["CVE-2099-0010"][0]["invasiveness"], "safe-probe")
        self.assertEqual(idx["CVE-2099-0011"][0]["invasiveness"], "intrusive")

    def test_shipped_library_and_playbooks_valid(self):
        from tw.playbooks import load_playbooks, load_products
        prods = load_products(json.loads((ROOT / "threatwatch/data/validation/products.json").read_text()))
        self.assertTrue(any("f5:nginx_open_source" in p["cpe"] for p in prods))
        pbs = load_playbooks(json.loads((ROOT / "threatwatch/data/validation/playbooks.json").read_text()))
        self.assertIn("CVE-2026-123007", pbs)

    def test_playbook_rejects_missing_source_and_bad_stage(self):
        from tw.playbooks import load_playbooks
        base = {"cve": "CVE-2099-0001", "reviewedBy": "x", "lastReviewed": "2026-11-21", "sources": ["https://example.com"],
                "steps": [{"stage": "exploit", "platform": "linux", "invasiveness": "passive", "title": "t",
                           "cmd": "true", "positive": "p", "negative": "n"}]}
        with self.assertRaisesRegex(ValueError, "stage must be one of"):
            load_playbooks({"playbooks": [base]})
        with self.assertRaisesRegex(ValueError, "https source"):
            load_playbooks({"playbooks": [{**base, "sources": ["http://insecure"]}]})


if __name__ == "__main__":
    unittest.main()
