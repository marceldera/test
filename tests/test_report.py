"""Tests for the seven-section daily report (synthetic CVE-2099 data)."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from tw import report as R  # noqa: E402

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
FIELDS = ["cve", "vendor", "product", "cvss", "severity", "kev", "detection", "exploitRef", "published", "fixRef",
          "zeroDay", "itw", "poc", "attack"]


def rec(cid, vendor, product, score, pub, cwes=(), kev=None, zero=False, itw=(), poc=0, affected=None,
        groups=(), techniques=()):
    sources = ([{"source": "CISA KEV", "date": kev["dateAdded"], "url": R.KEV_PAGE}] if kev else []) + list(itw)
    return {
        "cve": cid, "vendor": vendor, "product": product, "title": None,
        "description": f"{product} flaw lets a remote attacker do bad things.", "published": pub + "T10:00:00",
        "nvdStatus": "Analyzed", "cvss": {"score": score, "severity": "CRITICAL" if score >= 9 else "HIGH",
                                          "version": "3.1", "attackVector": "NETWORK", "privileges": "NONE",
                                          "userInteraction": "NONE"},
        "cwes": list(cwes), "affected": affected or [], "kev": kev, "fixRefs": [], "vendorRefs": [],
        "exploitRefs": [], "exploitation": {"zeroDay": zero, "inTheWild": bool(sources), "sources": sources},
        "zeroDay": {"rcaUrl": "https://example.com/rca"} if zero else None,
        "pocs": {"count": poc, "metasploit": [{"name": "m"}] * min(poc, 1), "githubTotal": max(poc - 1, 0)},
        "intel": {"groups": list(groups), "campaigns": []}, "attack": {"techniques": list(techniques)},
    }


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        kev = {"dateAdded": "2026-11-21", "dueDate": "2026-12-12", "ransomware": "known",
               "requiredAction": "Apply mitigations per vendor instructions."}
        self.recs = [
            rec("CVE-2099-0001", "ExampleCorp", "Gateway", 9.8, "2026-11-01", ["CWE-78"], kev=kev,
                affected=[{"vendor": "examplecorp", "product": "gateway", "versions": "< 4.2.1", "part": "a"}],
                techniques=[{"id": "T1190", "name": "Exploit Public-Facing Application",
                             "mappingType": "exploitation_technique", "via": "CTID KEV mapping"}]),
            rec("CVE-2099-0002", "MedAI", "Label Server", 9.8, "2026-11-20", ["CWE-22"],
                itw=[{"source": "ENISA EUVD (exploited)", "date": "2026-11-21", "url": "https://euvd.enisa.europa.eu/"}],
                groups=[{"id": "G9999", "name": "Example Panda", "url": "https://attack.mitre.org/groups/G9999"}]),
            rec("CVE-2099-0003", "Lib", "Crypto", 9.1, "2026-11-21", ["CWE-415"], poc=3),
            rec("CVE-2099-0004", "Old", "Thing", 9.9, "2026-08-01"),  # not new
        ]
        self.write_catalog()
        self.brief = {
            "edition": "2026-11-22", "window": {"start": "2026-11-21T11:50:00+00:00", "end": "2026-11-22T11:50:00+00:00"},
            "executive": {"counts": {"kevTotal": 1790}},
            "kevLatest": {"date": "2026-11-21", "dueDate": "2026-12-12", "catalogVersion": "2026.11.21",
                          "items": [{"cve": "CVE-2099-0001", "vendor": "ExampleCorp", "product": "Gateway"}]},
            "cves": [{"cve": "CVE-2099-0001", "vendor": "ExampleCorp", "product": "Gateway", "name": "Gateway RCE",
                      "kev": {"dateAdded": "2026-11-21", "dueDate": "2026-12-12", "ransomware": "known",
                              "requiredAction": "Apply mitigations per vendor instructions."}}],
            "changes": [],
        }

    def write_catalog(self):
        cdir = self.dir / "cves"
        rows = []
        for r in self.recs:
            p = cdir / r["cve"].split("-")[1] / f"{r['cve']}.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(r))
            rows.append([r["cve"], r["vendor"], r["product"], r["cvss"]["score"], r["cvss"]["severity"],
                         1 if r["kev"] else 0, 0, 0, r["published"][:10], 0, 1 if r["exploitation"]["zeroDay"] else 0,
                         1 if r["exploitation"]["inTheWild"] else 0, r["pocs"]["count"], 0])
        (cdir / "index.json").write_text(json.dumps({"fields": FIELDS, "items": rows}))
        (cdir / "epss.json").write_text(json.dumps({"scores": {"CVE-2099-0001": [0.91, 0.99]}}))

    def compose(self, track=None, editorial=None, brief=None):
        return R.compose(brief or self.brief, R.Catalog(self.dir), track or {}, editorial, NOW)

    def text(self, rep, sid):
        sec = next(s for s in rep["sections"] if s["id"] == sid)
        return json.dumps(sec["blocks"])

    def test_structure_and_selection(self):
        rep, track = self.compose()
        self.assertEqual(R.validate_report(rep), [])
        self.assertEqual([s["title"] for s in rep["sections"]][0], "Executive Intelligence Summary")
        self.assertEqual(rep["dateLabel"], "Sunday, November 22, 2026")
        self.assertEqual(rep["window"], "Reporting window: November 21-22, 2026")
        self.assertEqual(rep["footer"], "Enterprise Cyber Threat Intelligence | 22 Nov 2026")
        self.assertEqual(set(rep["prioritized"]), {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"})
        s1 = self.text(rep, "summary")
        self.assertIn("1,790", s1)
        self.assertIn("Top five actions", s1)
        self.assertIn("New zero-day / in-the-wild reports", s1)
        s2 = self.text(rep, "critical")
        self.assertIn("OS command injection (CVSS 9.8)", s2)
        self.assertIn("gateway 4.2.1", s2)          # fixed version from NVD range
        self.assertIn("91.0% probability", s2)
        self.assertIn("unvetted GitHub", s2)
        s3 = self.text(rep, "exploitation")
        self.assertIn("December 12, 2026", s3)
        self.assertIn("Example Panda (G9999)", s3)
        self.assertIn("Defensive hunting", s3)
        s4 = self.text(rep, "industry")
        self.assertIn("Healthcare / medical imaging", s4)
        s5 = self.text(rep, "actors")
        self.assertIn("T1190", s5)
        s6 = self.text(rep, "remediation")
        self.assertIn("Isolate immediately", s6)
        self.assertIn("2026-11-22", track["editions"])

    def test_changes_next_day(self):
        rep1, track = self.compose()
        # next day: the EUVD CVE lands in KEV and gains a PoC
        r = self.recs[1]
        r["kev"] = {"dateAdded": "2026-11-23", "dueDate": "2026-12-14", "ransomware": "unknown", "requiredAction": None}
        r["pocs"]["count"] = 1
        self.write_catalog()
        b2 = dict(self.brief, edition="2026-11-23", cves=[],
                  window={"start": "2026-11-22T11:50:00+00:00", "end": "2026-11-23T11:50:00+00:00"})
        rep2, track2 = self.compose(track, brief=b2)
        s7 = self.text(rep2, "changes")
        self.assertIn("Added to CISA KEV on 2026-11-23", s7)
        self.assertIn("public exploit code now referenced", s7)
        self.assertIn("No significant new development established since November 22", s7)
        self.assertNotIn("CVE-2099-0002", rep2["prioritized"])  # tracked, not re-prioritized
        # refreshing the same edition is idempotent
        rep3, _ = self.compose(track2, brief=b2)
        self.assertEqual(rep3["sections"], rep2["sections"])

    def test_editorial_override(self):
        ed = {"reviewedBy": "M. Dera", "report": R.safe_report_editorial({
            "window": "Reporting window: November 21-22, 2026",
            "sections": {"summary": [{"type": "p", "text": "Analyst **summary**."}]},
            "references": [{"label": "Advisory", "url": "https://example.com/a"}]})}
        rep, _ = self.compose(editorial=ed)
        self.assertEqual(rep["sections"][0]["source"], "editorial")
        self.assertEqual(rep["sections"][1]["source"], "generated")
        self.assertEqual(rep["references"], [{"label": "Advisory", "url": "https://example.com/a"}])
        self.assertEqual(rep["prepared"], "Analyst-reviewed edition")

    def test_editorial_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            R.safe_report_editorial({"sections": {"bogus": [{"type": "p", "text": "x"}]}})
        with self.assertRaises(ValueError):
            R.safe_report_editorial({"sections": {"summary": [{"type": "table", "columns": ["a", "b"], "rows": [["x"]]}]}})
        with self.assertRaises(ValueError):
            R.safe_report_editorial({"sections": {}, "references": [{"label": "x", "url": "javascript:alert(1)"}]})

    def test_empty_day(self):
        for r in self.recs:
            r["published"] = "2026-08-01T00:00:00"
            r["exploitation"] = {"zeroDay": False, "inTheWild": False, "sources": []}
            r["kev"] = None
        self.write_catalog()
        rep, _ = self.compose(brief=dict(self.brief, cves=[]))
        self.assertEqual(R.validate_report(rep), [])
        self.assertIn("No CVE met ThreatWatch prioritization criteria", self.text(rep, "summary"))
        self.assertIn("No new CISA KEV additions were verified", self.text(rep, "exploitation"))

    def test_monthly_summary(self):
        doc = {"month": "2026-11", "complete": False, "metrics": [{"id": "vendors", "value": 1}, {"id": "ransomware", "value": 1},
               {"id": "epss90", "value": 1}],
               "events": [{"date": "2026-11-21", "cve": "CVE-2099-0001", "vendor": "ExampleCorp", "product": "Gateway",
                           "concern": "Gateway RCE", "ransomware": "known"}]}
        rep = R.compose_month(doc, R.Catalog(self.dir), None, NOW)
        self.assertEqual(R.validate_report(rep, R.M_SECTION_IDS), [])
        self.assertEqual(rep["dateLabel"], "November 2026")
        self.assertIn("month to date", rep["window"])
        self.assertIn("CVE-2099-0002", self.text(rep, "exploitation"))      # EUVD-only, in month
        self.assertIn("ExampleCorp", self.text(rep, "industry"))
        chron = self.text(rep, "chronology")
        self.assertIn("known ransomware use", chron)
        self.assertEqual(rep["footer"], "Enterprise Cyber Threat Intelligence | November 2026")


if __name__ == "__main__":
    unittest.main()
