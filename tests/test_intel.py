"""Offline tests for zero-day, PoC and ATT&CK enrichment (synthetic CVE-2099 data)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from test_catalog import CatalogTests, nvd_rec  # noqa: E402
from tw import intel as I  # noqa: E402

P0_CSV = """CVE,Vendor,Product,Type,Description,Date Discovered,Date Patched,Advisory,Analysis URL,Root Cause Analysis,Reported By
CVE-2099-0001,ExampleCorp,Gateway,Memory Corruption,Heap overflow,2026-11-02,2026-11-19,https://example.com/adv,???,,Google Threat Intelligence Group
CVE-2099-0050,OtherCo,Browser,Use-after-free,UAF in renderer,???,2026-11-15,vendor.example (CVE-2099-0050),https://example.com/blog,https://example.com/rca,Anonymous
"""

EDB_CSV = """id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
51234,exploits/linux/remote/51234.py,ExampleCorp Gateway 1.4 - RCE,2026-11-05,someone,remote,linux,,2026-11-05,2026-11-05,1,CVE-2099-0010;OSVDB-1,,,,,
"""

MSF = {"exploit_linux/http/examplecorp_gateway_rce": {
    "name": "ExampleCorp Gateway Unauthenticated RCE", "fullname": "exploit/linux/http/examplecorp_gateway_rce",
    "rank": 600, "type": "exploit", "disclosure_date": "2026-11-03", "check": True,
    "references": ["CVE-2099-0001", "URL-https://example.com"], "path": "/modules/exploits/linux/http/examplecorp_gateway_rce.rb"}}


def attack_bundle():
    ref = lambda xid, kind: [{"source_name": "mitre-attack", "external_id": xid,  # noqa: E731
                              "url": f"https://attack.mitre.org/{kind}/{xid}"}]
    return {"objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "20.1"},
        {"type": "intrusion-set", "id": "intrusion-set--g", "name": "Example Panda", "external_references": ref("G9999", "groups")},
        {"type": "campaign", "id": "campaign--c", "name": "Operation Test", "external_references": ref("C9999", "campaigns")},
        {"type": "attack-pattern", "id": "attack-pattern--t", "name": "Exploit Public-Facing Application",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1190",
                                  "url": "https://attack.mitre.org/techniques/T1190"}]},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "campaign--c",
         "target_ref": "attack-pattern--t", "description": "During Operation Test, actors exploited CVE-2099-0001."},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "attributed-to",
         "source_ref": "campaign--c", "target_ref": "intrusion-set--g"},
    ]}


CTID = {"mapping_objects": [
    {"capability_id": "CVE-2099-0001", "attack_object_id": "T1190", "attack_object_name": "Exploit Public-Facing Application",
     "mapping_type": "exploitation_technique", "status": "complete", "comments": "Crafted HTTP request."},
    {"capability_id": "CVE-2099-0001", "attack_object_id": "T1059", "attack_object_name": "Command and Scripting Interpreter",
     "mapping_type": "primary_impact", "status": "complete"}]}


class IntelTests(CatalogTests):
    test_build = test_cached_index_and_reviews = test_bad_review_blocks = None  # covered in test_catalog

    def setUp(self):
        super().setUp()
        (self.fx / "p0-All.csv").write_text(P0_CSV)
        (self.fx / "edb.csv").write_text(EDB_CSV)
        self.w("msf.json", MSF)
        self.w("attack.json", attack_bundle())
        self.w("ctid-kev.json", CTID)
        self.w("euvd-0.json", {"items": [{"id": "EUVD-2099-1", "aliases": "CVE-2099-0060\nGHSA-xxxx",
                                          "exploitedSince": "Nov 10, 2026, 12:00:00 AM"}], "total": 1})
        self.w("nvd-pub-0.json", {"totalResults": 1, "vulnerabilities": [{"cve": nvd_rec("CVE-2099-0070", 3.1)}]})
        poc = self.data.parent / "poc" / "2099"
        poc.mkdir(parents=True)
        (poc / "CVE-2099-0010.json").write_text(json.dumps([
            {"full_name": "a/low", "html_url": "https://github.com/a/low", "stargazers_count": 1, "fork": False},
            {"full_name": "b/top", "html_url": "https://github.com/b/top", "stargazers_count": 40, "fork": False,
             "pushed_at": "2026-11-06T00:00:00Z", "description": "PoC"},
            {"full_name": "c/fork", "html_url": "https://github.com/c/fork", "stargazers_count": 99, "fork": True}]))

    def run_cat(self, nuclei=True, **env):
        env.setdefault("TW_POC_DIR", str(self.data.parent / "poc"))
        return super().run_cat(nuclei, **env)

    def test_enrichment(self):
        r = self.run_cat()
        self.assertEqual(r.returncode, 0, r.stderr)
        idx = json.loads((self.data / "cves" / "index.json").read_text())
        ids = {row[0] for row in idx["items"]}
        # zero-day only in Project Zero / EUVD (no NVD, no KEV) is still catalogued; pub backfill added 0070
        self.assertTrue({"CVE-2099-0050", "CVE-2099-0060", "CVE-2099-0070"} <= ids)
        a = self.rec("CVE-2099-0001")
        self.assertTrue(a["exploitation"]["zeroDay"])
        self.assertEqual([s["source"] for s in a["exploitation"]["sources"]],
                         ["CISA KEV", "Google Project Zero (0day In the Wild)"])
        self.assertEqual(a["zeroDay"]["discovered"], "2026-11-02")
        self.assertIsNone(a["zeroDay"]["analysisUrl"])  # "???" stays null
        self.assertEqual(a["pocs"]["metasploit"][0]["rank"], "excellent")
        self.assertTrue(a["exploitStatus"]["publicExploitReference"])
        self.assertEqual([g["id"] for g in a["intel"]["groups"]], ["G9999"])  # via campaign attribution
        self.assertEqual([c["id"] for c in a["intel"]["campaigns"]], ["C9999"])
        t = a["attack"]["techniques"]
        self.assertEqual([x["id"] for x in t], ["T1190", "T1059"])
        self.assertIn("CTID KEV mapping", t[0]["via"])
        b = self.rec("CVE-2099-0010")
        self.assertEqual(b["pocs"]["exploitdb"][0]["url"], "https://www.exploit-db.com/exploits/51234")
        self.assertEqual(b["pocs"]["githubTotal"], 2)  # forks ignored
        self.assertEqual(b["pocs"]["github"][0]["repo"], "b/top")
        z = self.rec("CVE-2099-0050")
        self.assertTrue(z["nvdPending"])
        self.assertEqual((z["vendor"], z["product"]), ("OtherCo", "Browser"))
        self.assertEqual(z["zeroDay"]["rcaUrl"], "https://example.com/rca")
        e = self.rec("CVE-2099-0060")
        self.assertEqual(e["exploitation"]["sources"][0]["date"], "2026-11-10")
        st = json.loads((self.data / "cves" / "status.json").read_text())
        self.assertEqual(st["counts"]["zeroDay"], 2)
        self.assertEqual(st["sources"]["intel"]["attackVersion"], "20.1")
        state = json.loads((self.data / "cves" / "state.json").read_text())
        self.assertEqual(state["scope"], 2)

    def test_feed_outage_keeps_last_good(self):
        self.assertEqual(self.run_cat().returncode, 0)
        (self.fx / "msf.json").unlink()
        (self.fx / "p0-All.csv").unlink()
        r = self.run_cat()
        self.assertEqual(r.returncode, 0, r.stderr)
        a = self.rec("CVE-2099-0001")
        self.assertTrue(a["exploitation"]["zeroDay"])  # cached Project Zero copy
        self.assertEqual(len(a["pocs"]["metasploit"]), 1)
        st = json.loads((self.data / "cves" / "status.json").read_text())
        self.assertFalse(st["sources"]["intel"]["metasploit"]["ok"])
        self.assertTrue(any("Metasploit" in w for w in st["warnings"]))


class ParserTests(unittest.TestCase):
    def test_p0_header_detection_and_dates(self):
        d = I.parse_p0_csv('"0day In the Wild"\n\n' + P0_CSV)
        self.assertEqual(set(d), {"CVE-2099-0001", "CVE-2099-0050"})
        self.assertIsNone(d["CVE-2099-0050"]["discovered"])
        self.assertIsNone(d["CVE-2099-0050"]["advisoryUrl"])  # no https URL in the cell

    def test_unsafe_urls_dropped(self):
        top, n = I.parse_poc_file([{"full_name": "x/y", "html_url": "javascript:alert(1)", "fork": False}])
        self.assertEqual((top, n), ([], 1))

    def test_euvd_refuses_unfiltered_response(self):
        import os, tempfile
        d = Path(tempfile.mkdtemp())
        (d / "euvd-0.json").write_text(json.dumps({"total": 244503, "items": [
            {"id": "EUVD-2025-1", "aliases": "CVE-2025-34025\n", "datePublished": "May 21, 2025, 10:11:32 PM"}]}))
        os.environ["TW_FIXTURES"] = str(d)
        try:
            with self.assertRaises(I.SourceError):
                I.collect_euvd()
        finally:
            os.environ.pop("TW_FIXTURES", None)

    def test_euvd_date_format(self):
        self.assertEqual(I._euvd_date("Sep 9, 2024, 12:00:00 AM"), "2024-09-09")
        self.assertIn("/api/search?exploited=true", I.EUVD_URL)


del CatalogTests  # run the base tests once, from test_catalog

if __name__ == "__main__":
    unittest.main()
