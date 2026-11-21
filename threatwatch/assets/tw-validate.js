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
        kev = $("vf-kev").checked, det = $("vf-det").checked, exp = $("vf-exp").checked;
    return idx.items.filter(function (r) {
      var o = row(r);
      if (q && (o.cve + " " + o.vendor + " " + o.product).toLowerCase().indexOf(q) < 0) return false;
      if (sev === "NONE" ? o.severity : sev && o.severity !== sev) return false;
      if (kev && !o.kev) return false;
      if (det && !o.detection) return false;
      if (exp && !o.exploitRef) return false;
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
          o.kev ? el("span", { cls: "chip kev", text: "KEV" }) : null,
          o.exploitRef ? el("span", { cls: "chip exp", text: "Exploit ref" }) : null,
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
    var inIndex = idx && idx.items.some(function (r) { return r[0] === cve; });
    if (idx && !inIndex) { notFound(d, cve); return; }
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
    var exploit = r.exploitStatus || {};
    var badges = [
      ["kev", !!r.kev, "KEV-listed", r.kev ? "Added " + r.kev.dateAdded + (r.kev.ransomware === "known" ? " · ransomware use known" : "") : "Not in CISA KEV"],
      ["epss", !!(e && e.percentile >= 0.95), "High EPSS", e ? (e.score * 100).toFixed(1) + "% · " + pct(e.percentile) + " pct · " + (epss.date || "date unknown") : "EPSS unknown"],
      ["crit", !!(cv && cv.score >= 9), "Critical CVSS", cv ? "CVSS " + cv.version + " " + cv.score + " " + (cv.severity || "") : "Not scored"],
      ["exp", !!exploit.publicExploitReference, "Public exploit reported", exploit.publicExploitReference ? r.exploitRefs.length + " reference(s) tagged Exploit by NVD" : "No exploit reference in NVD"],
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

    // validation panel
    var vp = el("section", { cls: "card", "aria-labelledby": "vp-h" }, [el("h3", { id: "vp-h", text: "Validation methods" })]);
    if (!r.detections.length) {
      vp.appendChild(el("p", { text: "No reliable public detection check is indexed for this CVE." }));
      vp.appendChild(el("p", { cls: "muted", text: "Validate through inventory: compare installed versions (from the asset owner, package manager or management console) with the vendor’s fixed versions." }));
    }
    r.detections.forEach(function (x) {
      var chips = [
        el("span", { cls: "chip" + (x.reviewStatus === "reviewed" ? " det" : x.reviewStatus === "rejected" ? " kev" : ""),
          text: x.reviewStatus === "reviewed" ? "Reviewed by Aegis " + (x.lastReviewed || "") : x.reviewStatus === "rejected" ? "Rejected by Aegis" : "Not reviewed by Aegis" }),
        el("span", { cls: "chip" + (x.invasiveness === "intrusive" ? " kev" : ""), text: x.invasiveness === "intrusive" ? "Intrusive — needs approval" :
          x.invasiveness === "passive" ? "Passive" : "Active request · not tagged intrusive" }),
        x.outOfBand ? el("span", { cls: "chip exp", text: "Out-of-band callback" }) : null,
        x.upstreamVerified ? el("span", { cls: "chip", text: "Publisher-verified" }) : null,
        x.protocol ? el("span", { cls: "chip", text: x.protocol }) : null
      ];
      var title = { nuclei: "Nuclei template", "nmap-nse": "Nmap NSE script", "vendor-script": "Vendor detection script",
        "config-check": "Configuration check", "authenticated-check": "Authenticated check", manual: "Manual verification" }[x.method] || x.method;
      vp.appendChild(el("div", { cls: "det" }, [
        el("h4", { text: title + (x.name ? " — " + x.name : "") }),
        el("div", { cls: "chips" }, chips),
        x.path ? el("p", { cls: "mono muted", text: x.path }) : null,
        x.reviewNote ? el("p", { text: x.reviewNote }) : null,
        el("p", { cls: "muted" }, [x.publisher || "", x.url ? " · " : "", x.url ? link(x.url, "View source") : null])
      ]));
    });
    vp.appendChild(el("p", { cls: "muted" }, ["Only run checks against systems you own or are authorized to assess. ", el("a", { href: "#safe", text: "How to validate safely" })]));
    left.appendChild(vp);

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

    // exploit status
    right.appendChild(el("section", { cls: "card" }, [el("h3", { text: "Exploit status" }), el("ul", { cls: "plain" }, [
      el("li", { text: "CISA KEV: " + (r.kev ? "exploitation reported (listed " + r.kev.dateAdded + ")" : "not listed") }),
      el("li", null, ["Public exploit or PoC reference: ", r.exploitRefs.length ? "" : "none in NVD"].concat(
        r.exploitRefs.map(function (u, i) { return el("span", null, [i ? ", " : "", link(u, "ref " + (i + 1))]); }))),
      el("li", { text: "Compromise of a specific system: cannot be determined from public data." })
    ]), el("p", { cls: "muted", text: exploit.note || "" })]));

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
      pv.detections ? el("li", { text: "Nuclei templates · commit " + unknown(status && status.sources && status.sources.nucleiCommit) }) : null,
      status ? el("li", { text: "Catalog last updated " + fmtTime(status.lastSuccessAt) }) : null
    ])]));
  }

  // Deterministic rubric — mirrored in docs/THREATWATCH.md.
  function priority(r, e, exposure, crit) {
    var reasons = [], tier;
    var cv = r.cvss ? r.cvss.score : null, highE = e && e.percentile >= 0.95, exp = r.exploitStatus && r.exploitStatus.publicExploitReference;
    if (exposure === "none") return { tier: "Not applicable", window: "No action if the affected product isn’t deployed — confirm through inventory.", reasons: ["You selected “Not deployed”."] };
    if (r.kev) reasons.push("Exploitation reported by CISA KEV.");
    if (highE) reasons.push("EPSS in the top 5% of scored CVEs.");
    if (cv != null) reasons.push("CVSS " + cv + "."); else reasons.push("No CVSS score yet.");
    if (exp) reasons.push("Public exploit reference reported.");
    var t;
    if (r.kev && exposure !== "internal") t = 1;
    else if (cv >= 9 && exp && exposure === "internet") t = 1;
    else if (r.kev || highE || (cv >= 9 && exposure === "internet")) t = 2;
    else if (cv >= 7) t = 3;
    else t = 4;
    if (exposure === "unknown") reasons.push("Exposure unknown — treated as possibly internet-facing.");
    if (exposure === "internet") reasons.push("Internet-facing.");
    if (exposure === "internal") reasons.push("Internal only.");
    if (crit === "high" && t > 1) { t--; reasons.push("High asset criticality raised the tier."); }
    if (crit === "low" && t < 4 && !r.kev) { t++; reasons.push("Low asset criticality lowered the tier."); }
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

  ["vf-sev", "vf-epss", "vf-kev", "vf-det", "vf-exp"].forEach(function (id) { $(id).addEventListener("change", function () { page = 0; renderResults(); }); });
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
    getJSON("data/latest.json").catch(function () { return null; })
  ]).then(function (res) {
    idx = res[0]; epss = res[1] || { scores: {} }; status = res[2];
    if (status && res[3]) status.latestEdition = res[3].edition;
    if (idx) F = idx.fields;
    renderStatus();
    if (idx) renderResults(); else $("vv-count").textContent = "";
    route();
    renderPlan();
  });
})();
