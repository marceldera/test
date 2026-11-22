/* Aegis ThreatWatch — Vulnerability Validation (Phase 1, read-only).
 * Reads only public generated JSON. Never scans. No innerHTML with data.
 */
(function () {
  "use strict";
  var PAGE = 50, STALE_HOURS = 36;
  var CVE_RE = /^CVE-\d{4}-\d{4,}$/;
  var idx = null, F = null, epss = { scores: {} }, status = null, page = 0, last = [];
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k]; else if (k === "cls") n.className = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null && c !== false) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function safeHref(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null; }
  function link(u, t) { var h = safeHref(u); return h ? el("a", { href: h, rel: "noopener noreferrer", text: t || h }) : document.createTextNode(t || ""); }
  function getJSON(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }); }
  function pct(v) { return (v * 100).toFixed(v >= 0.995 ? 1 : 0) + "th"; }
  function fmtTime(iso) {
    try { return new Date(iso).toLocaleString("en-US", { timeZone: "America/New_York", dateStyle: "medium", timeStyle: "short" }) + " ET"; }
    catch (e) { return iso; }
  }
  function pocSummary(p) {
    var parts = [];
    if ((p.metasploit || []).length) parts.push(p.metasploit.length + " Metasploit");
    if ((p.exploitdb || []).length) parts.push(p.exploitdb.length + " Exploit-DB");
    if (p.githubTotal) parts.push(p.githubTotal + " GitHub");
    if ((p.vulncheckXdb || []).length) parts.push(p.vulncheckXdb.length + " VulnCheck XDB");
    if ((p.nvdTagged || []).length) parts.push(p.nvdTagged.length + " NVD-tagged");
    return parts.join(" · ") || "Reported";
  }
  function unknown(v) { return v == null || v === "" ? "Unknown" : String(v); }
  function row(r) { var o = {}; F.forEach(function (f, i) { o[f] = r[i]; }); return o; }
  function ep(cve) { var s = epss.scores[cve]; return s ? { score: s[0], percentile: s[1] } : null; }

  // ------------------------------------------------------------------ routing
  function current() { var p = new URLSearchParams(location.search); return (p.get("cve") || "").trim().toUpperCase(); }
  function go(cve, push) {
    var url = cve ? "?cve=" + encodeURIComponent(cve) : location.pathname;
    if (push) history.pushState({ cve: cve }, "", url);
    route();
  }
  window.addEventListener("popstate", route);
  function route() {
    var c = current();
    if (c) { $("vv-search-view").hidden = true; $("vv-detail").hidden = false; showDetail(c); }
    else { $("vv-detail").hidden = true; $("vv-search-view").hidden = false; document.title = "Vulnerability Validation | Aegis ThreatWatch"; }
  }

  // ------------------------------------------------------------------ search
  function filtered() {
    if (!idx) return [];
    var q = $("vv-q").value.trim().toLowerCase(), sev = $("vf-sev").value, minE = parseFloat($("vf-epss").value) || 0,
        kev = $("vf-kev").checked, det = $("vf-det").checked, exp = $("vf-exp").checked,
        zd = $("vf-zd").checked, itw = $("vf-itw").checked, att = $("vf-att").checked;
    return idx.items.filter(function (r) {
      var o = row(r);
      if (q && (o.cve + " " + o.vendor + " " + o.product).toLowerCase().indexOf(q) < 0) return false;
      if (sev === "NONE" ? o.severity : sev && o.severity !== sev) return false;
      if (kev && !o.kev) return false;
      if (det && !o.detection) return false;
      if (exp && !(o.poc || o.exploitRef)) return false;
      if (zd && !o.zeroDay) return false;
      if (itw && !(o.itw || o.kev)) return false;
      if (att && !o.attack) return false;
      if (minE) { var e = ep(o.cve); if (!e || e.percentile < minE) return false; }
      return true;
    });
  }
  function renderResults() {
    last = filtered();
    var tb = $("vv-results").querySelector("tbody"); tb.textContent = "";
    var total = last.length, pages = Math.max(1, Math.ceil(total / PAGE));
    page = Math.min(page, pages - 1);
    $("vv-count").textContent = total + " CVE" + (total === 1 ? "" : "s") + " match" + (total === 1 ? "es" : "") +
      (total ? "." : ". Try a CVE ID, vendor or product, or clear the filters.");
    last.slice(page * PAGE, page * PAGE + PAGE).forEach(function (r) {
      var o = row(r), e = ep(o.cve);
      var a = el("a", { href: "?cve=" + o.cve, text: o.cve });
      a.addEventListener("click", function (ev) { ev.preventDefault(); go(o.cve, true); window.scrollTo(0, 0); });
      var cb = el("input", { type: "checkbox", "aria-label": "Add " + o.cve + " to test plan" });
      cb.checked = inPlan(o.cve); cb.disabled = !cb.checked && plan.length >= PLAN_MAX;
      cb.addEventListener("change", function () { togglePlan(o.cve); });
      tb.appendChild(el("tr", null, [
        el("td", null, [cb]),
        el("td", null, [a]),
        el("td", { text: [o.vendor, o.product].filter(Boolean).join(" ") || "Unknown" }),
        el("td", { text: o.cvss != null ? o.cvss + " " + (o.severity || "") : "Not scored" }),
        el("td", { text: e ? pct(e.percentile) : "Unknown" }),
        el("td", null, [el("span", { cls: "chips" }, [
          o.zeroDay ? el("span", { cls: "chip zd", text: "Zero-day" }) : null,
          o.kev ? el("span", { cls: "chip kev", text: "KEV" }) : (o.itw ? el("span", { cls: "chip kev", text: "Exploited" }) : null),
          (o.poc || o.exploitRef) ? el("span", { cls: "chip exp", text: o.poc ? "PoC ×" + o.poc : "Exploit ref" }) : null,
          o.attack ? el("span", { cls: "chip att", text: "ATT&CK" }) : null,
          o.detection ? el("span", { cls: "chip det", text: "Detection" }) : null,
          o.fixRef ? el("span", { cls: "chip fix", text: "Fix ref" }) : null])]),
        el("td", { text: o.published || "Unknown" })
      ]));
    });
    var pg = $("vv-pager"); pg.textContent = "";
    if (pages > 1) {
      var prev = el("button", { type: "button", cls: "btn secondary", text: "← Previous" });
      var next = el("button", { type: "button", cls: "btn secondary", text: "Next →" });
      prev.disabled = page === 0; next.disabled = page >= pages - 1;
      prev.addEventListener("click", function () { page--; renderResults(); });
      next.addEventListener("click", function () { page++; renderResults(); });
      pg.appendChild(prev); pg.appendChild(el("span", { cls: "muted", text: "Page " + (page + 1) + " of " + pages })); pg.appendChild(next);
    }
  }

  // ------------------------------------------------------------------ detail
  function showDetail(cve) {
    var d = $("vv-detail"); d.textContent = "";
    var back = el("a", { href: location.pathname, cls: "vv-back", text: "← Back to CVE search" });
    back.addEventListener("click", function (ev) { ev.preventDefault(); go("", true); });
    d.appendChild(back);
    if (!CVE_RE.test(cve)) {
      d.appendChild(el("p", { cls: "notice", text: "“" + cve.slice(0, 40) + "” isn’t a valid CVE ID. Use the format CVE-YYYY-NNNN." }));
      return;
    }
    document.title = cve + " — Vulnerability Validation | Aegis ThreatWatch";
    if (!idx) {
      d.appendChild(el("h2", { text: cve }));
      d.appendChild(el("p", { cls: "notice", text: "The CVE catalog hasn’t been built yet, so no CVE can be looked up here at the moment. It is generated automatically after the next published daily brief." }));
      d.appendChild(el("p", null, ["Meanwhile, see the official record on ", link("https://nvd.nist.gov/vuln/detail/" + cve, "NVD"),
        " or ", link("https://www.cve.org/CVERecord?id=" + cve, "CVE.org"), ", or today’s ", el("a", { href: "./", text: "daily brief" }), "."]));
      return;
    }
    var inIndex = idx.items.some(function (r) { return r[0] === cve; });
    if (!inIndex) { notFound(d, cve); return; }
    d.appendChild(el("p", { cls: "muted", text: "Loading " + cve + "…" }));
    getJSON("data/cves/" + cve.split("-")[1] + "/" + cve + ".json").then(function (r) {
      d.removeChild(d.lastChild); renderRecord(d, r);
    }).catch(function () { d.removeChild(d.lastChild); notFound(d, cve); });
  }

  function notFound(d, cve) {
    d.appendChild(el("h2", { text: cve }));
    d.appendChild(el("p", { cls: "notice", text: "This CVE isn’t in the ThreatWatch catalog. " + ((status && status.coverage) || "") }));
    d.appendChild(el("p", null, ["Check the official record on ", link("https://nvd.nist.gov/vuln/detail/" + cve, "NVD"),
      " or ", link("https://www.cve.org/CVERecord?id=" + cve, "CVE.org"), ". No EPSS, KEV or detection data is shown because none is held here — that is not the same as zero risk."]));
  }

  function renderRecord(d, r) {
    var e = ep(r.cve), cv = r.cvss;
    d.appendChild(el("div", { cls: "vv-head" }, [el("h2", { text: r.cve }),
      el("span", { cls: "meta", text: [r.vendor, r.product].filter(Boolean).join(" ") || "Product unknown" })]));
    var pb = el("button", { type: "button", cls: "btn secondary", id: "plan-toggle" });
    function pbText() { pb.textContent = inPlan(r.cve) ? "✓ In test plan — remove" : "Add to controlled test plan"; pb.disabled = !inPlan(r.cve) && plan.length >= PLAN_MAX; }
    pb.addEventListener("click", function () { togglePlan(r.cve); pbText(); });
    pbText();
    d.appendChild(el("p", null, [pb, " ", el("a", { href: "#plan", text: "View plan" })]));
    if (r.title) d.appendChild(el("p", { cls: "lead", text: r.title }));
    if (r.description) d.appendChild(el("p", { text: r.description }));
    if (r.nvdPending) d.appendChild(el("p", { cls: "notice", text: "NVD details for this CVE haven’t been collected yet. CVSS and affected versions show as Unknown until the next catalog runs fill them in." }));

    // risk badges
    var exploit = r.exploitStatus || {}, xp = r.exploitation || {}, pocs = r.pocs || {}, intel = r.intel || {};
    var others = (xp.sources || []).filter(function (s) { return s.source !== "CISA KEV"; });
    var badges = [
      ["zd", !!xp.zeroDay, "Zero-day (in the wild)", xp.zeroDay ? "Tracked by Google Project Zero" + (r.zeroDay && r.zeroDay.discovered ? " · discovered " + r.zeroDay.discovered : "") : "Not in Project Zero’s tracker"],
      ["kev", !!r.kev, "KEV-listed", r.kev ? "Added " + r.kev.dateAdded + (r.kev.ransomware === "known" ? " · ransomware use known" : "") : "Not in CISA KEV"],
      ["epss", !!(e && e.percentile >= 0.95), "High EPSS", e ? (e.score * 100).toFixed(1) + "% · " + pct(e.percentile) + " pct · " + (epss.date || "date unknown") : "EPSS unknown"],
      ["crit", !!(cv && cv.score >= 9), "Critical CVSS", cv ? "CVSS " + cv.version + " " + cv.score + " " + (cv.severity || "") : "Not scored"],
      ["itw", others.length > 0, "Other exploitation reports", others.length ? others.map(function (s) { return s.source; }).join(", ") : "None beyond KEV"],
      ["exp", !!exploit.publicExploitReference, "Public exploit / PoC", exploit.publicExploitReference ? pocSummary(pocs) : "None found in Metasploit, Exploit-DB, GitHub or NVD"],
      ["fix", r.fixRefs.length > 0, "Vendor fix / mitigation", r.fixRefs.length ? r.fixRefs.length + " patch or mitigation reference(s)" : "None referenced in NVD"]
    ];
    d.appendChild(el("div", { cls: "badges", role: "list", "aria-label": "Risk indicators" }, badges.map(function (b) {
      return el("div", { cls: "rbadge " + b[0] + (b[1] ? " on" : " off"), role: "listitem" },
        [el("b", { text: b[2] + (b[1] ? "" : ": no") }), el("span", { text: b[3] })]);
    })));
    d.appendChild(el("p", { cls: "muted", text: "High EPSS = 95th percentile or above. These indicators are separate kinds of evidence — none on its own means a specific system is vulnerable or compromised." }));

    // evidence ribbon
    var usable = r.detections.filter(function (x) { return x.reviewStatus !== "rejected"; });
    var reviewed = usable.filter(function (x) { return x.reviewStatus === "reviewed"; });
    d.appendChild(el("section", { cls: "card", "aria-labelledby": "rib-h" }, [
      el("h3", { id: "rib-h", text: "Evidence path" }),
      el("ol", { cls: "ribbon" }, [
        el("li", { cls: "met" }, [el("span", { cls: "st", text: "Advisory" }), el("strong", { text: "Published" }),
          el("p", { text: r.published ? "NVD published " + r.published.slice(0, 10) + "." : (r.kev ? "Listed by CISA KEV." : "Advisory date unknown.") })]),
        el("li", null, [el("span", { cls: "st", text: "Possible exposure" }), el("strong", { text: "Check your inventory" }),
          el("p", { text: r.affected.length ? "Exposed only if you run an affected product and version (see Affected)." : "Affected versions not yet published by NVD; use the vendor advisory." })]),
        el("li", { cls: usable.length ? "" : "na" }, [el("span", { cls: "st", text: "Detection signal" }),
          el("strong", { text: usable.length ? usable.length + " public check" + (usable.length > 1 ? "s" : "") : "No public check indexed" }),
          el("p", { text: usable.length ? (reviewed.length ? reviewed.length + " reviewed by Aegis. " : "Not yet reviewed by Aegis. ") + "A positive result is a signal for analyst review, not a confirmed finding." : "Rely on version and configuration checks." })]),
        el("li", { cls: "na" }, [el("span", { cls: "st", text: "Analyst-confirmed" }), el("strong", { text: "Requires authorized testing" }),
          el("p", { text: "Only after authorized testing and human review. Never inferred from public data." })])
      ])
    ]));

    d.appendChild(renderPlaybook(r));
    var left = el("div"), right = el("div");
    d.appendChild(el("div", { cls: "vv-grid" }, [left, right]));

    // facts
    var facts = [
      ["CVSS", cv ? cv.score + " " + (cv.severity || "") + " (v" + cv.version + ", source " + unknown(cv.source) + ")" : "Unknown"],
      ["Vector", cv ? unknown(cv.vector) : "Unknown"],
      ["Attack / auth / UI", cv ? [unknown(cv.attackVector), "privileges " + unknown(cv.privileges), "user interaction " + unknown(cv.userInteraction)].join(" · ") : "Unknown"],
      ["EPSS", e ? (e.score * 100).toFixed(2) + "% probability · " + pct(e.percentile) + " percentile · model date " + (epss.date || "unknown") : "Unknown (no EPSS score published)"],
      ["CISA KEV", r.kev ? "Listed " + r.kev.dateAdded + " · federal due date " + unknown(r.kev.dueDate) + " · ransomware use " + r.kev.ransomware : "Not listed"],
      ["Required action (KEV)", r.kev ? unknown(r.kev.requiredAction) : "—"],
      ["Weakness", r.cwes.length ? r.cwes.join(", ") : "Unknown"],
      ["NVD status", unknown(r.nvdStatus) + (r.lastModified ? " · modified " + r.lastModified.slice(0, 10) : "")]
    ];
    var dl = el("dl", { cls: "facts" });
    facts.forEach(function (f) { dl.appendChild(el("dt", { text: f[0] })); dl.appendChild(el("dd", { text: f[1] })); });
    left.appendChild(el("section", { cls: "card" }, [el("h3", { text: "Key facts" }), dl]));

    // affected
    var aff = el("section", { cls: "card" }, [el("h3", { text: "Affected products (NVD CPE configuration)" })]);
    if (!r.affected.length) aff.appendChild(el("p", { cls: "muted", text: "Unknown — NVD hasn’t published affected configurations. Use the vendor advisory." }));
    else {
      aff.appendChild(el("div", { cls: "tbl-wrap" }, [el("table", null, [
        el("thead", null, [el("tr", null, ["Vendor", "Product", "Vulnerable versions"].map(function (h) { return el("th", { scope: "col", text: h }); }))]),
        el("tbody", null, r.affected.map(function (a) { return el("tr", null, [el("td", { text: a.vendor }), el("td", { text: a.product }), el("td", { cls: "mono", text: a.versions })]); }))])]));
      if (r.affectedTruncated) aff.appendChild(el("p", { cls: "muted", text: "More configurations exist; see NVD." }));
      aff.appendChild(el("p", { cls: "muted", text: "“< X” means versions before X are listed as vulnerable. Confirm the fixed version in the vendor advisory — backports can differ." }));
    }
    left.appendChild(aff);

    // priority calculator (right)
    var expSel = el("select", { id: "pc-exp" }, [["unknown", "Unknown"], ["internet", "Internet-facing"], ["internal", "Internal only"], ["none", "Not deployed"]]
      .map(function (o) { return el("option", { value: o[0], text: o[1] }); }));
    var critSel = el("select", { id: "pc-crit" }, [["unknown", "Unknown"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]
      .map(function (o) { return el("option", { value: o[0], text: o[1] }); }));
    var out = el("div", { "aria-live": "polite" });
    right.appendChild(el("section", { cls: "card", "aria-labelledby": "pc-h" }, [
      el("h3", { id: "pc-h", text: "Priority for your environment" }),
      el("p", { cls: "muted", text: "Optional. Nothing you choose here leaves your browser." }),
      el("div", { cls: "calc" }, [el("label", null, ["Exposure", expSel]), el("label", null, ["Asset criticality", critSel])]),
      out,
      el("p", { cls: "muted", text: "Guidance only, not policy. Response windows are suggestions." })
    ]));
    function calc() { out.textContent = ""; var p = priority(r, e, expSel.value, critSel.value);
      out.appendChild(el("div", { cls: "tier", text: p.tier })); out.appendChild(el("p", { text: p.window }));
      out.appendChild(el("ul", { cls: "plain" }, p.reasons.map(function (t) { return el("li", { text: t }); }))); }
    expSel.addEventListener("change", calc); critSel.addEventListener("change", calc); calc();

    // exploitation intelligence
    var xli = (xp.sources || []).map(function (s) {
      return el("li", null, [link(s.url, s.source), s.date ? " · " + s.date : ""]);
    });
    if (!xli.length) xli.push(el("li", { text: "No exploitation reported by CISA KEV, Project Zero, ENISA EUVD or VulnCheck." }));
    var zcard = [el("h3", { text: "Exploitation & zero-day intelligence" }), el("ul", { cls: "plain" }, xli)];
    var z = r.zeroDay;
    if (z) {
      var zdl = el("dl", { cls: "facts" });
      [["Type", z.type], ["Discovered in the wild", z.discovered], ["Patched", z.patched], ["Reported by", z.reportedBy]].forEach(function (f) {
        zdl.appendChild(el("dt", { text: f[0] })); zdl.appendChild(el("dd", { text: unknown(f[1]) }));
      });
      zcard.push(el("p", { cls: "muted", text: "Google Project Zero tracks this as a zero-day exploited before a fix was available." }), zdl);
      var zl = [["Vendor advisory", z.advisoryUrl], ["Technical analysis", z.analysisUrl], ["Root cause analysis", z.rcaUrl]]
        .filter(function (x) { return safeHref(x[1]); }).map(function (x) { return el("li", null, [link(x[1], x[0])]); });
      if (zl.length) zcard.push(el("ul", { cls: "plain" }, zl));
    }
    if (intel.ransomware === "known") zcard.push(el("p", { cls: "notice", text: "Known use in ransomware campaigns." }));
    if ((intel.exploitationReports || []).length) zcard.push(el("p", null, ["Exploitation reports (VulnCheck): "].concat(
      intel.exploitationReports.slice(0, 6).map(function (x, i) { return el("span", null, [i ? ", " : "", link(x.url, x.added || "report " + (i + 1))]); }))));
    zcard.push(el("p", { cls: "muted", text: "Compromise of a specific system can’t be determined from public data. " + (exploit.note || "") }));
    right.appendChild(el("section", { cls: "card" }, zcard));

    // public exploits & PoCs
    var pc = [el("h3", { text: "Public exploits & proof-of-concept code" })];
    function pgroup(title, items, fn) { if (items && items.length) pc.push(el("h4", { text: title }), el("ul", { cls: "plain" }, items.map(fn))); }
    pgroup("Metasploit modules", pocs.metasploit, function (m) {
      return el("li", null, [link(m.url, m.module || m.name), " · " + [m.type, m.rank && m.rank + " rank", m.check ? "has check()" : null].filter(Boolean).join(" · ")]);
    });
    pgroup("Exploit-DB", pocs.exploitdb, function (x) {
      return el("li", null, [link(x.url, "EDB-" + x.id), " · " + [x.title, x.type, x.verified ? "verified" : "unverified", x.published].filter(Boolean).join(" · ")]);
    });
    pgroup("VulnCheck XDB", pocs.vulncheckXdb, function (x) { return el("li", null, [link(x.url, x.type || "exploit"), x.added ? " · " + x.added : ""]); });
    pgroup("GitHub PoCs (top " + (pocs.github || []).length + " of " + (pocs.githubTotal || 0) + " by stars)", pocs.github, function (g) {
      return el("li", null, [link(g.url, g.repo), " · ★" + g.stars + (g.updated ? " · updated " + g.updated : "") + (g.description ? " — " + g.description : "")]);
    });
    pgroup("References tagged Exploit by NVD", pocs.nvdTagged || r.exploitRefs, function (u, i) { return el("li", null, [link(u)]); });
    if (pc.length === 1) pc.push(el("p", { cls: "muted", text: "No public exploit or PoC found in Metasploit, Exploit-DB, GitHub (PoC-in-GitHub) or NVD references." }));
    else pc.push(el("p", { cls: "notice", text: "Links only — nothing is downloaded or run. GitHub PoCs are unvetted and sometimes contain malware: review code in an isolated lab, never on production, and only against systems you are authorized to test." }));
    right.appendChild(el("section", { cls: "card" }, pc));

    // MITRE ATT&CK and threat actors
    var tech = (r.attack && r.attack.techniques) || [];
    var ac = [el("h3", { text: "Threat actors & MITRE ATT&CK" })];
    function agroup(title, items) { if (items && items.length) ac.push(el("h4", { text: title }), el("ul", { cls: "plain" }, items.map(function (x) { return el("li", null, [link(x.url, x.id + " " + (x.name || ""))]); }))); }
    agroup("Groups", intel.groups); agroup("Campaigns", intel.campaigns); agroup("Software", intel.software);
    if (tech.length) ac.push(el("h4", { text: "Techniques" }), el("ul", { cls: "plain" }, tech.map(function (t) {
      var kind = { exploitation_technique: "how it’s exploited", primary_impact: "primary impact", secondary_impact: "secondary impact" }[t.mappingType];
      return el("li", null, [link(t.url, t.id + " " + (t.name || "")), " · " + [kind, t.via].filter(Boolean).join(" · ")]);
    })));
    var cm = tech.filter(function (t) { return t.comment; })[0];
    if (cm) ac.push(el("p", { cls: "muted", text: "CTID note: " + cm.comment }));
    if (ac.length === 1) ac.push(el("p", { cls: "muted", text: "No ATT&CK group, campaign or technique cites this CVE yet." }));
    else ac.push(el("p", { cls: "muted", text: "Groups, campaigns and software are listed only where MITRE ATT&CK’s own text cites this CVE. Technique mappings come from ATT&CK procedure examples and the Center for Threat-Informed Defense KEV mappings." }));
    right.appendChild(el("section", { cls: "card" }, ac));

    // references with copy
    var refs = [{ label: "NVD", url: "https://nvd.nist.gov/vuln/detail/" + r.cve }];
    if (r.kev) refs.push({ label: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" });
    r.vendorRefs.concat(r.fixRefs).forEach(function (x) { if (!refs.some(function (y) { return y.url === x.url; })) refs.push({ label: x.tags.join(", ") || "Reference", url: x.url }); });
    r.references.forEach(function (x) { if (refs.length < 14 && !refs.some(function (y) { return y.url === x.url; })) refs.push({ label: x.tags.join(", ") || "Reference", url: x.url }); });
    right.appendChild(el("section", { cls: "card" }, [el("h3", { text: "Primary references" }),
      el("ul", { cls: "plain refs" }, refs.map(function (x) {
        var b = el("button", { type: "button", cls: "btn secondary copy", text: "Copy", "aria-label": "Copy link: " + x.label });
        b.addEventListener("click", function () { copy(x.url, b); });
        return el("li", null, [el("span", { cls: "muted", text: x.label + ": " }), link(x.url), b]);
      }))]));

    // related ThreatWatch content
    var ap = r.appearsIn || {}, rel = [];
    (ap.briefs || []).slice(-5).reverse().forEach(function (b) {
      var isLatest = b === (status && status.latestEdition);
      rel.push(el("li", null, [isLatest ? el("a", { href: "./", text: "Daily brief " + b + " (today’s edition)" }) : "Daily brief " + b]));
    });
    (ap.months || []).forEach(function (m) { rel.push(el("li", null, [el("a", { href: "./#monthly", text: "Monthly summary " + m })])); });
    right.appendChild(el("section", { cls: "card" }, [el("h3", { text: "In ThreatWatch" }),
      rel.length ? el("ul", { cls: "plain" }, rel) : el("p", { cls: "muted", text: "Not yet featured in a daily brief or monthly summary." })]));

    // provenance
    var pv = r.provenance || {};
    right.appendChild(el("section", { cls: "card" }, [el("h3", { text: "Sources & freshness" }), el("ul", { cls: "plain" }, [
      pv.nvd ? el("li", null, [link(pv.nvd.url, "NVD"), " · record modified " + unknown(pv.nvd.lastModified).slice(0, 10)]) : el("li", { text: "NVD: not yet collected" }),
      pv.kev ? el("li", null, [link(pv.kev.url, "CISA KEV"), " · catalog " + unknown(pv.kev.catalogVersion) + " · fetched " + fmtTime(pv.kev.fetchedAt)]) : null,
      el("li", { text: "FIRST EPSS · model date " + unknown(epss.date) }),
      el("li", { text: "Zero-day & exploit intelligence: Project Zero, ENISA EUVD, VulnCheck, Metasploit, Exploit-DB, PoC-in-GitHub · MITRE ATT&CK " + unknown(status && status.sources && status.sources.intel && status.sources.intel.attackVersion) }),
      pv.detections ? el("li", { text: "Nuclei templates · commit " + unknown(status && status.sources && status.sources.nucleiCommit) }) : null,
      status ? el("li", { text: "Catalog last updated " + fmtTime(status.lastSuccessAt) }) : null
    ])]));
  }

  // Deterministic rubric — mirrored in docs/THREATWATCH.md.
  function priority(r, e, exposure, crit) {
    var reasons = [], tier;
    var cv = r.cvss ? r.cvss.score : null, highE = e && e.percentile >= 0.95, exp = r.exploitStatus && r.exploitStatus.publicExploitReference;
    if (exposure === "none") return { tier: "Not applicable", window: "No action if the affected product isn’t deployed — confirm through inventory.", reasons: ["You selected “Not deployed”."] };
    var itw = !!(r.kev || (r.exploitation && r.exploitation.inTheWild));
    if (r.kev) reasons.push("Exploitation reported by CISA KEV.");
    else if (itw) reasons.push("Exploitation reported by " + r.exploitation.sources.map(function (s) { return s.source; }).join(", ") + ".");
    if (r.exploitation && r.exploitation.zeroDay) reasons.push("Exploited as a zero-day (Google Project Zero).");
    if (highE) reasons.push("EPSS in the top 5% of scored CVEs.");
    if (cv != null) reasons.push("CVSS " + cv + "."); else reasons.push("No CVSS score yet.");
    if (exp) reasons.push("Public exploit or PoC code available.");
    var t;
    if (itw && exposure !== "internal") t = 1;
    else if (cv >= 9 && exp && exposure === "internet") t = 1;
    else if (itw || highE || (cv >= 9 && exposure === "internet")) t = 2;
    else if (cv >= 7) t = 3;
    else t = 4;
    if (exposure === "unknown") reasons.push("Exposure unknown — treated as possibly internet-facing.");
    if (exposure === "internet") reasons.push("Internet-facing.");
    if (exposure === "internal") reasons.push("Internal only.");
    if (crit === "high" && t > 1) { t--; reasons.push("High asset criticality raised the tier."); }
    if (crit === "low" && t < 4 && !itw) { t++; reasons.push("Low asset criticality lowered the tier."); }
    tier = ["", "Tier 1 — Immediate", "Tier 2 — High", "Tier 3 — Planned", "Tier 4 — Monitor"][t];
    var win = ["", "Mitigate or isolate within 24–72 hours; patch as soon as a fix is validated.",
      "Remediate within about 7–14 days, or by the KEV due date if sooner.", "Remediate in the next scheduled patch cycle.",
      "Track for changes in exploitation, EPSS or exposure."][t];
    return { tier: tier, window: win, reasons: reasons };
  }

  function copy(text, btn) {
    var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy"; }, 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { btn.textContent = "Copy failed"; });
    else btn.textContent = "Copy unavailable";
  }

  // ------------------------------------------------------------------ validation playbook
  var ctx = { products: [], playbooks: {} };
  function download(name, text, type) {
    var blob = new Blob([text], { type: type || "text/plain" });
    var u = URL.createObjectURL(blob), a = el("a", { href: u, download: name });
    document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(u); }, 1000);
  }
  function validTarget() { var t = (opts.target || "").trim(); return t && TARGET_RE.test(t) ? t : ""; }
  function chip(text, cls) { return el("span", { cls: "chip" + (cls ? " " + cls : ""), text: text }); }

  function renderPlaybook(r) {
    var P = window.TWPlaybook, m = P.build(r, ctx);
    var sec = el("section", { cls: "card playbook", id: "playbook", "aria-labelledby": "pbk-h" });
    sec.appendChild(el("h3", { id: "pbk-h", text: "Validation playbook" }));
    sec.appendChild(el("div", { cls: "chips" }, [
      m.curated ? chip("Reviewed by " + m.curated.reviewedBy + " · " + m.curated.lastReviewed, "det") : chip("Generated — not CVE-specific review", ""),
      chip(m.groups.length + " affected product" + (m.groups.length === 1 ? "" : "s"), ""),
      chip(r.detections.length ? r.detections.length + " public detection check" + (r.detections.length > 1 ? "s" : "") : "No public detection check", r.detections.length ? "det" : "")
    ]));
    sec.appendChild(el("p", { cls: "muted", text: "Ordered from least to most invasive. Work top to bottom and stop when you have enough evidence. Version + configuration evidence from steps 1–2 usually validates a CVE without probing anything. Run only against systems you own or are authorized to test." }));
    if (m.curated) {
      sec.appendChild(el("p", { text: m.curated.summary }));
      if (m.curated.conditions) sec.appendChild(el("div", null, [el("strong", { text: "Vulnerable when all of these are true:" }),
        el("ul", { cls: "plain" }, m.curated.conditions.map(function (c) { return el("li", { text: c }); }))]));
      if (m.curated.fixedVersions) sec.appendChild(el("div", { cls: "tbl-wrap" }, [el("table", null, [
        el("caption", { text: "Affected and fixed versions" }),
        el("thead", null, [el("tr", null, ["Product", "Affected", "Fixed"].map(function (h) { return el("th", { scope: "col", text: h }); }))]),
        el("tbody", null, m.curated.fixedVersions.map(function (f) { return el("tr", null, [el("td", { text: f.product }), el("td", { cls: "mono", text: f.affected || "" }), el("td", { cls: "mono", text: f.fixed })]); }))])]));
    } else {
      sec.appendChild(el("p", { cls: "notice", text: "No Aegis-reviewed playbook for this CVE yet. The steps below come from the NVD affected-product data, the Aegis product library and public detection checks. Read the vendor advisory for configuration prerequisites and fixed versions." }));
    }

    // target (local only)
    var tgt = el("input", { type: "text", id: "pbk-target", autocomplete: "off", spellcheck: "false", placeholder: "https://app.example.com or 203.0.113.10", value: opts.target });
    var tmsg = el("span", { cls: "muted" });
    sec.appendChild(el("div", { cls: "pbk-target" }, [el("label", { "for": "pbk-target", text: "Target for network steps (optional; stays in your browser and fills HOST/TARGET in the commands)" }), tgt, tmsg]));

    if (m.others.length) sec.appendChild(el("p", { cls: "muted", text: "Also listed by NVD — check with the vendor or distribution advisory: " +
      m.others.map(function (g) { return g.name + " (" + g.ranges.join("; ") + ")"; }).join(", ") + "." }));
    var body = el("div");
    sec.appendChild(body);
    function draw() {
      body.textContent = "";
      var t = validTarget();
      tmsg.textContent = opts.target && !t ? " Use a single hostname, IP or http(s) URL." : "";
      P.STAGES.forEach(function (stg) {
        var list = m.steps[stg[0]];
        var box = el("div", { cls: "stage" }, [el("h4", { text: stg[1] }), el("p", { cls: "muted", text: stg[2] })]);
        if (!list.length) box.appendChild(el("p", { cls: "muted", text: stg[0] === "configuration" ? "No CVE-specific condition is recorded. Check the vendor advisory for required features, modules or exposed interfaces." :
          stg[0] === "detection" ? "No public Nuclei template or Nmap script is indexed for this CVE. Validate with version + configuration evidence." :
          stg[0] === "mitigation" ? "Apply the vendor's fixed version (see the references); use vendor-documented workarounds only." : "No step." }));
        list.forEach(function (st) {
          var cmd = P.fill(st.cmd, t), isText = st.platform === "web-ui" || (st.platform === "appliance-cli" && /→/.test(st.cmd));
          var cp = el("button", { type: "button", cls: "btn secondary copy", text: "Copy" });
          cp.addEventListener("click", function () { copy(cmd, cp); });
          var src = { curated: ["Reviewed by Aegis", "det"], library: ["Aegis product library", ""], generic: ["Generic search — adjust the name", "exp"],
            nuclei: [st.reviewStatus === "reviewed" ? "Nuclei · reviewed by Aegis" : "Nuclei · community, not reviewed", st.reviewStatus === "reviewed" ? "det" : ""],
            "nmap-nse": ["Nmap official script", ""] }[st.source] || ["", ""];
          box.appendChild(el("div", { cls: "step" }, [
            el("div", { cls: "step-h" }, [el("strong", { text: st.title })]),
            el("div", { cls: "chips" }, [chip(P.PLATFORM[st.platform] || st.platform),
              chip(st.invasiveness === "intrusive" ? "Intrusive — needs approval" : st.invasiveness === "passive" ? "Read-only" : "Non-intrusive probe", st.invasiveness === "intrusive" ? "kev" : ""),
              src[0] ? chip(src[0], src[1]) : null, st.outOfBand ? chip("Out-of-band callback", "exp") : null]),
            isText ? el("p", { text: cmd }) : el("div", { cls: "cmdrow" }, [el("pre", { cls: "plan-cmd" }, [el("code", { text: cmd })]), cp]),
            el("p", { cls: "pn" }, [el("b", { text: "Positive: " }), st.positive]),
            el("p", { cls: "pn" }, [el("b", { text: "Negative: " }), st.negative]),
            st.url ? el("p", { cls: "muted" }, [link(st.url, "Review the check source before running it")]) : null
          ]));
        });
        body.appendChild(box);
      });
      if (m.curated && m.curated.mitigations) body.appendChild(el("div", { cls: "stage" }, [el("h4", { text: "Mitigation notes" }),
        el("ul", { cls: "plain" }, m.curated.mitigations.map(function (x) { return el("li", { text: x }); }))]));
      if (m.curated && m.curated.notes) body.appendChild(el("ul", { cls: "plain muted" }, m.curated.notes.map(function (x) { return el("li", { text: x }); })));
      body.appendChild(el("div", { cls: "stage" }, [el("h4", { text: "Decide and record" }), el("div", { cls: "tbl-wrap" }, [el("table", null, [
        el("thead", null, [el("tr", null, [el("th", { scope: "col", text: "Finding" }), el("th", { scope: "col", text: "Status" })])]),
        el("tbody", null, P.DECISION.map(function (x) { return el("tr", null, [el("td", { text: x[0] }), el("td", { text: x[1] })]); }))])])]));
      if (m.curated) body.appendChild(el("p", { cls: "muted" }, ["Playbook sources: "].concat(m.curated.sources.map(function (u, i) { return el("span", null, [i ? " · " : "", link(u, u.replace(/^https:\/\//, "").split("/")[0])]); }))));
    }
    tgt.addEventListener("input", function () { opts.target = tgt.value; draw(); });
    draw();

    var dmd = el("button", { type: "button", cls: "btn", text: "Download playbook checklist (.md)" });
    dmd.addEventListener("click", function () { download(r.cve + "-validation-playbook.md", P.md([m], { target: validTarget() }), "text/markdown"); });
    var dsh = el("button", { type: "button", cls: "btn secondary", text: "Download Linux check script (.sh)" });
    dsh.addEventListener("click", function () { download("aegis-validate-" + r.cve + ".sh", P.bash([m], {}), "text/x-shellscript"); });
    var ps = P.ps1([m]);
    var dps = ps ? el("button", { type: "button", cls: "btn secondary", text: "Download Windows check script (.ps1)" }) : null;
    if (dps) dps.addEventListener("click", function () { download("aegis-validate-" + r.cve + ".ps1", ps, "text/plain"); });
    sec.appendChild(el("p", { cls: "dl-row" }, [dmd, " ", dsh, dps ? " " : null, dps]));
    sec.appendChild(el("p", { cls: "muted", text: "The check scripts are read-only: they run only local version, package and configuration queries, make no network connections and change nothing. Review them before running." }));
    return sec;
  }

  // ------------------------------------------------------------------ controlled test plan
  // Built entirely in the browser. Nothing (targets, CVEs, attestations) is sent anywhere.
  var PLAN_MAX = 25, PLAN_KEY = "tw-test-plan", plan = [], recCache = {};
  var TARGET_RE = /^(https?:\/\/)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(:\d{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/;
  try { plan = (JSON.parse(localStorage.getItem(PLAN_KEY) || "[]") || []).filter(function (c) { return CVE_RE.test(c); }).slice(0, PLAN_MAX); } catch (e) { plan = []; }
  function savePlan() { try { localStorage.setItem(PLAN_KEY, JSON.stringify(plan)); } catch (e) { /* storage unavailable: plan lasts this visit */ } }
  function inPlan(c) { return plan.indexOf(c) >= 0; }
  function togglePlan(c) {
    if (inPlan(c)) plan.splice(plan.indexOf(c), 1); else if (plan.length < PLAN_MAX) plan.push(c);
    savePlan(); renderPlan(); if (!current()) renderResults();
  }
  function getRecord(c) {
    if (recCache[c]) return Promise.resolve(recCache[c]);
    return getJSON("data/cves/" + c.split("-")[1] + "/" + c + ".json").then(function (r) { recCache[c] = r; return r; })
      .catch(function () { return { cve: c, missing: true, detections: [] }; });
  }
  var opts = { target: "", intrusive: false, oast: false, rate: "10", operator: "", authRef: "", a1: false, a2: false, a3: false, a4: false };

  function planRows(records) {
    return records.map(function (r) {
      var t = (r.detections || []).filter(function (x) { return x.method === "nuclei" && x.reviewStatus !== "rejected"; });
      var runnable = t.filter(function (x) { return (opts.intrusive || x.invasiveness !== "intrusive") && (opts.oast || !x.outOfBand); });
      var reason = r.missing ? "Not in catalog" : !t.length ? "No public template — use an inventory/version check"
        : !runnable.length ? (t.some(function (x) { return x.invasiveness === "intrusive"; }) && !opts.intrusive ? "Skipped: only intrusive template(s)" : "Skipped: needs out-of-band callbacks")
        : "Included";
      return { r: r, templates: t, runnable: runnable, included: runnable.length > 0, reason: reason };
    });
  }

  function buildCommand(rows, stamp) {
    var ids = rows.filter(function (x) { return x.included; }).map(function (x) { return x.r.cve; });
    var t = opts.target.trim();
    var lines = [
      "# Aegis ThreatWatch controlled test — generated " + stamp,
      "# Scope: " + ids.length + " CVE template(s) only. Run ONLY against systems you are authorized to test.",
      t ? null : "# targets.txt must list one authorized target per line, nothing else.",
      "nuclei -ut   # install/update templates first",
      "nuclei -id " + ids.join(",") + " \\",
      t ? "  -u '" + t + "' \\" : "  -l targets.txt \\"
    ].filter(function (x) { return x !== null; });
    var flags = [];
    if (!opts.intrusive) flags.push("-etags intrusive,dos,fuzz");
    if (!opts.oast) flags.push("-ni");
    if (flags.length) lines.push("  " + flags.join(" ") + " \\");
    lines.push("  -rl " + opts.rate + " -c 5 -timeout 10 \\");
    lines.push("  -jsonl -o aegis-controlled-test-" + stamp.slice(0, 16).replace(/[-:T]/g, "") + ".jsonl");
    return { ids: ids, text: lines.join("\n") };
  }

  function renderPlan() {
    var j = $("plan-jump"); if (j) j.textContent = "Controlled test plan (" + plan.length + ")";
    var root = $("plan-body"); if (!root) return;
    if (!plan.length) {
      root.textContent = "";
      root.appendChild(el("p", { cls: "muted", text: "No CVEs selected yet. Tick the Plan box in the search results, or use “Add to controlled test plan” on a CVE page. Up to " + PLAN_MAX + " CVEs." }));
      return;
    }
    Promise.all(plan.map(getRecord)).then(function (records) { drawPlan(root, planRows(records)); });
  }

  function drawPlan(root, rows) {
    root.textContent = "";
    // selected CVEs
    root.appendChild(el("div", { cls: "tbl-wrap" }, [el("table", null, [
      el("caption", { text: plan.length + " of " + PLAN_MAX + " CVEs selected. Only these are tested." }),
      el("thead", null, [el("tr", null, ["CVE", "Product", "Public check", "In this test", ""].map(function (h) { return el("th", { scope: "col", text: h }); }))]),
      el("tbody", null, rows.map(function (x) {
        var rm = el("button", { type: "button", cls: "btn secondary copy", text: "Remove", "aria-label": "Remove " + x.r.cve + " from plan" });
        rm.addEventListener("click", function () { togglePlan(x.r.cve); });
        var t0 = x.templates[0];
        return el("tr", null, [
          el("td", { cls: "mono" }, [el("a", { href: "?cve=" + x.r.cve, text: x.r.cve })]),
          el("td", { text: [x.r.vendor, x.r.product].filter(Boolean).join(" ") || "Unknown" }),
          el("td", { text: t0 ? "Nuclei" + (x.templates.length > 1 ? " ×" + x.templates.length : "") + " · " +
            (t0.invasiveness === "intrusive" ? "intrusive" : "not tagged intrusive") + (t0.outOfBand ? " · out-of-band" : "") +
            (t0.reviewStatus === "reviewed" ? " · reviewed by Aegis" : " · not reviewed by Aegis") : "None" }),
          el("td", null, [el("span", { cls: "badge " + (x.included ? "b-ok" : "b-neutral"), text: x.included ? "Included" : "Not run" }), " ", x.included ? "" : x.reason]),
          el("td", null, [rm])
        ]);
      }))])]));
    var clear = el("button", { type: "button", cls: "btn secondary", text: "Clear plan" });
    clear.addEventListener("click", function () { plan = []; savePlan(); renderPlan(); if (!current()) renderResults(); });
    root.appendChild(el("p", null, [clear]));

    // options
    var tgt = el("input", { type: "text", id: "plan-target", autocomplete: "off", spellcheck: "false", placeholder: "https://app.example.com or 203.0.113.10", value: opts.target });
    var tgtMsg = el("span", { cls: "muted", id: "plan-target-msg" });
    var intr = el("input", { type: "checkbox", id: "plan-intr" }); intr.checked = opts.intrusive;
    var oast = el("input", { type: "checkbox", id: "plan-oast" }); oast.checked = opts.oast;
    var rate = el("select", { id: "plan-rate" }, ["5", "10", "25"].map(function (v) { var o = el("option", { value: v, text: v + " requests/second" }); if (v === opts.rate) o.selected = true; return o; }));
    root.appendChild(el("fieldset", { cls: "card plan-fs" }, [el("legend", { text: "Test options" }),
      el("label", { "for": "plan-target", text: "Target (optional — stays in your browser; leave blank to use a targets.txt file)" }), tgt, tgtMsg,
      el("label", { cls: "chk" }, [intr, " Include templates tagged intrusive / DoS / fuzz (off by default; needs owner approval and a maintenance window)"]),
      el("label", { cls: "chk" }, [oast, " Allow out-of-band callbacks (off by default; sends interaction data to an external OAST server)"]),
      el("label", { "for": "plan-rate", text: "Rate limit" }), rate]));

    // attestation
    var a = [["a1", "I own the target system(s) or have explicit written authorization to test them."],
             ["a2", "The test stays within the agreed scope and time window, and the system owner and security operations have been told."],
             ["a3", "I understand checks send real network requests that can trigger alerts or affect fragile systems."],
             ["a4", "I will treat any positive result as suspected until a qualified person confirms it, and I accept the disclaimer below."]];
    var boxes = a.map(function (x) { var c = el("input", { type: "checkbox", id: "plan-" + x[0] }); c.checked = opts[x[0]]; return [x[0], c, x[1]]; });
    var op = el("input", { type: "text", id: "plan-op", autocomplete: "name", value: opts.operator, placeholder: "Your name" });
    var ref = el("input", { type: "text", id: "plan-ref", autocomplete: "off", value: opts.authRef, placeholder: "e.g. ROE-2026-014 or change ticket" });
    root.appendChild(el("fieldset", { cls: "card plan-fs" }, [el("legend", { text: "Authorization (required)" })]
      .concat(boxes.map(function (b) { return el("label", { cls: "chk" }, [b[1], " " + b[2]]); }))
      .concat([el("label", { "for": "plan-op", text: "Tester name (required, for your record)" }), op,
               el("label", { "for": "plan-ref", text: "Authorization reference (optional)" }), ref])));

    var models = rows.filter(function (x) { return !x.r.missing; }).map(function (x) { return window.TWPlaybook.build(x.r, ctx); });
    if (models.length) {
      var b1 = el("button", { type: "button", cls: "btn secondary", text: "Download combined playbook (.md)" });
      b1.addEventListener("click", function () { download("aegis-validation-playbook-" + new Date().toISOString().slice(0, 10) + ".md", window.TWPlaybook.md(models, { target: validTarget(), tester: opts.operator.trim() }), "text/markdown"); });
      var b2 = el("button", { type: "button", cls: "btn secondary", text: "Download combined Linux check script (.sh)" });
      b2.addEventListener("click", function () { download("aegis-validate-plan.sh", window.TWPlaybook.bash(models, {}), "text/x-shellscript"); });
      var ps = window.TWPlaybook.ps1(models), b3 = null;
      if (ps) { b3 = el("button", { type: "button", cls: "btn secondary", text: "Download combined Windows script (.ps1)" }); b3.addEventListener("click", function () { download("aegis-validate-plan.ps1", ps); }); }
      root.appendChild(el("div", { cls: "card" }, [el("h3", { text: "Validation playbooks for this plan" }),
        el("p", { cls: "muted", text: "Step-by-step checklist for every selected CVE (inventory → configuration → exposure → detection → remediation → verification), plus read-only scripts that collect version and configuration evidence on each host." }),
        el("p", { cls: "dl-row" }, [b1, " ", b2, b3 ? " " : null, b3])]));
    }
    var out = el("div", { id: "plan-out", "aria-live": "polite" });
    root.appendChild(out);

    function update() {
      opts.target = tgt.value; opts.intrusive = intr.checked; opts.oast = oast.checked; opts.rate = rate.value;
      opts.operator = op.value; opts.authRef = ref.value;
      boxes.forEach(function (b) { opts[b[0]] = b[1].checked; });
      var rows2 = planRows(rows.map(function (x) { return x.r; }));
      var tOk = !opts.target.trim() || TARGET_RE.test(opts.target.trim());
      tgtMsg.textContent = tOk ? "" : " Use a single hostname, IP address or http(s) URL — no spaces or special characters.";
      out.textContent = "";
      var attested = boxes.every(function (b) { return b[1].checked; }) && opts.operator.trim().length > 1;
      var runnable = rows2.filter(function (x) { return x.included; }).length;
      if (!attested) { out.appendChild(el("p", { cls: "notice", text: "Tick all four authorization statements and enter your name to generate the test." })); return; }
      if (!tOk) { out.appendChild(el("p", { cls: "notice", text: "Fix the target before generating the test." })); return; }
      if (!runnable) { out.appendChild(el("p", { cls: "notice", text: "None of the selected CVEs has a public template that fits these options. Use inventory and version checks instead (see How to validate safely)." })); return; }
      var stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
      var cmd = buildCommand(rows2, stamp);
      var pre = el("pre", { cls: "plan-cmd", tabindex: "0", "aria-label": "Generated command" }, [el("code", { text: cmd.text })]);
      var cp = el("button", { type: "button", cls: "btn", text: "Copy command" });
      cp.addEventListener("click", function () { copy(cmd.text, cp); });
      var dl = el("button", { type: "button", cls: "btn secondary", text: "Download test record (.json)" });
      dl.addEventListener("click", function () {
        var rec = {
          record: "Aegis ThreatWatch controlled test plan", generatedAt: stamp, tester: opts.operator.trim(),
          authorizationReference: opts.authRef.trim() || null,
          attestations: a.map(function (x) { return x[1]; }),
          scope: { targets: opts.target.trim() ? [opts.target.trim()] : "targets.txt (authorized targets only)",
                   cves: rows2.map(function (x) { return { cve: x.r.cve, included: x.included, reason: x.reason,
                     templates: x.runnable.map(function (t) { return { path: t.path, invasiveness: t.invasiveness, outOfBand: t.outOfBand, reviewStatus: t.reviewStatus }; }) }; }) },
          options: { includeIntrusive: opts.intrusive, allowOutOfBand: opts.oast, rateLimitPerSecond: Number(opts.rate) },
          command: cmd.text,
          templatesIndexedCommit: (status && status.sources && status.sources.nucleiCommit) || null,
          resultHandling: "Positive results are suspected findings until confirmed by a qualified person. No result does not prove the system is not vulnerable.",
          note: "Generated in the browser. Aegis did not run this test and received none of this information."
        };
        var blob = new Blob([JSON.stringify(rec, null, 2)], { type: "application/json" });
        var u = URL.createObjectURL(blob), aEl = el("a", { href: u, download: "aegis-controlled-test-" + stamp.slice(0, 10) + ".json" });
        document.body.appendChild(aEl); aEl.click(); document.body.removeChild(aEl); setTimeout(function () { URL.revokeObjectURL(u); }, 1000);
      });
      out.appendChild(el("h3", { text: "Your controlled test (" + cmd.ids.length + " CVE" + (cmd.ids.length > 1 ? "s" : "") + ")" }));
      out.appendChild(pre);
      out.appendChild(el("p", null, [cp, " ", dl]));
      out.appendChild(el("ul", { cls: "plain muted" }, [
        el("li", { text: "-id limits the run to the selected CVE templates only; nothing else is tested." }),
        el("li", { text: (opts.intrusive ? "Intrusive templates are INCLUDED. " : "-etags excludes intrusive, DoS and fuzzing templates. ") + (opts.oast ? "Out-of-band callbacks are ALLOWED." : "-ni disables out-of-band callbacks.") }),
        el("li", { text: "Templates were indexed by Aegis at commit " + ((status && status.sources && status.sources.nucleiCommit) || "unknown") + "; your local templates may be newer. Review each template before running it." }),
        el("li", { text: "Record the results file with your test record. Treat findings as suspected until confirmed, and re-test after remediation." })
      ]));
    }
    [tgt, op, ref].forEach(function (i) { i.addEventListener("input", update); });
    [intr, oast, rate].concat(boxes.map(function (b) { return b[1]; })).forEach(function (i) { i.addEventListener("change", update); });
    update();
  }

  // ------------------------------------------------------------------ boot
  function renderStatus() {
    var s = $("vv-status"); s.textContent = "";
    if (!idx) { s.textContent = "The CVE catalog hasn’t been published yet. It appears after the first scheduled run."; return; }
    var age = status && status.lastSuccessAt ? (Date.now() - Date.parse(status.lastSuccessAt)) / 36e5 : null;
    s.appendChild(el("span", { cls: "badge " + (age != null && age > STALE_HOURS ? "b-urgent" : "b-ok"), text: age != null && age > STALE_HOURS ? "Stale" : "Current" }));
    s.appendChild(document.createTextNode(" " + idx.count.toLocaleString() + " CVEs · updated " + fmtTime((status && status.lastSuccessAt) || idx.generatedAt) +
      " · EPSS model date " + (epss.date || "unknown") + ". " + ((status && status.coverage) || "")));
    if (status && status.ok === false) s.appendChild(el("span", { cls: "notice", text: " The latest refresh failed checks; the last verified catalog is shown." }));
  }

  ["vf-sev", "vf-epss", "vf-kev", "vf-det", "vf-exp", "vf-zd", "vf-itw", "vf-att"].forEach(function (id) { $(id).addEventListener("change", function () { page = 0; renderResults(); }); });
  $("vv-q").addEventListener("input", function () { page = 0; if (!current()) renderResults(); });
  $("vv-filters").addEventListener("submit", function (e) { e.preventDefault(); });
  $("vf-reset").addEventListener("click", function () { $("vv-filters").reset(); $("vv-q").value = ""; page = 0; renderResults(); });
  $("vv-search").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var q = $("vv-q").value.trim().toUpperCase();
    if (CVE_RE.test(q)) { go(q, true); return; }
    page = 0; if (current()) go("", true); renderResults();
  });

  Promise.all([
    getJSON("data/cves/index.json").catch(function () { return null; }),
    getJSON("data/cves/epss.json").catch(function () { return { scores: {} }; }),
    getJSON("data/cves/status.json").catch(function () { return null; }),
    getJSON("data/latest.json").catch(function () { return null; }),
    getJSON("data/validation/products.json").catch(function () { return { products: [] }; }),
    getJSON("data/validation/playbooks.json").catch(function () { return { playbooks: [] }; })
  ]).then(function (res) {
    idx = res[0]; epss = res[1] || { scores: {} }; status = res[2];
    ctx.products = (res[4] && res[4].products) || [];
    (res[5] && res[5].playbooks || []).forEach(function (p) { ctx.playbooks[p.cve] = p; });
    if (status && res[3]) status.latestEdition = res[3].edition;
    if (idx) F = idx.fields;
    renderStatus();
    if (idx) renderResults(); else $("vv-count").textContent = "";
    route();
    renderPlan();
  });
})();
