/* AEGIS Global Intelligence — single assessment page (assessment.html?id=GI-...).
   Facts, attributed claims and AEGIS analysis are rendered as visibly distinct blocks. textContent only. */
(function () {
  "use strict";
  var PRI_LABEL = { CRITICAL: "Critical", HIGH: "High", MODERATE: "Moderate", LOW: "Low" };
  var HIST_LABEL = { published: "Published", substantive: "Substantive update", evidence_status: "Evidence status change",
    priority: "Priority change", trend: "Trend change", correction: "Correction", resolved: "Resolved" };
  var ID_RE = /^GI-(?:DEMO-)?\d{4}-\d{3,4}$/;
  var box = document.getElementById("gi-asm");

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k];
      else if (k === "cls") n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function getJSON(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }); }
  function fmt(ts, withTime) {
    if (!ts) return "—";
    var day = ts.length === 10;
    var d = new Date(day ? ts + "T12:00:00Z" : ts);
    var o = { month: "long", day: "numeric", year: "numeric", timeZone: day ? "UTC" : "America/New_York" };
    if (withTime && !day) { o.hour = "numeric"; o.minute = "2-digit"; o.timeZoneName = "short"; }
    return isNaN(d) ? "—" : d.toLocaleString("en-US", o);
  }
  function ext(url, text) {
    return el("a", { href: url, target: "_blank", rel: "noopener noreferrer nofollow", text: text || url });
  }
  function section(title, kids) { return el("section", { cls: "doc-sec" }, [el("h2", { text: title })].concat(kids)); }
  function refs(ids) { return el("span", { cls: "refs", text: ids.map(function (i) { return "[" + (i + 1) + "]"; }).join("") }); }
  function block(kind, label, claim) {
    var p = el("p", null, [claim.text, " ", refs(claim.sources)]);
    var lbl = label + (claim.attributed_to ? " · attributed to " + claim.attributed_to : "");
    return el("div", { cls: "gi-block " + kind }, [el("span", { cls: "lbl", text: lbl }), p]);
  }
  function list(items) { return el("ul", { cls: "gi-list" }, items.map(function (t) { return el("li", { text: t }); })); }
  function fail(msg) { box.textContent = ""; box.appendChild(el("p", { text: msg })); }

  var id = new URLSearchParams(location.search).get("id") || "";
  if (!ID_RE.test(id)) { fail("No assessment was selected. Return to the dashboard and choose an event."); return; }

  Promise.all(["data/active-threats.json", "data/historical-threats.json", "data/signals.json"].map(function (u) {
    return getJSON(u).catch(function () { return { records: [] }; });
  })).then(function (d) {
    var all = [].concat(d[0].records || [], d[1].records || [], d[2].records || []);
    var r = all.filter(function (x) { return x.id === id; })[0];
    if (!r) { fail("Assessment " + id + " is not published. It may have been withdrawn before publication or the link may be wrong."); return; }
    render(r);
  }).catch(function () { fail("The assessment could not be loaded. Please try again later."); });

  function render(r) {
    document.title = r.title + " · AEGIS Global Intelligence";
    if (r.demo) document.getElementById("gi-demo").hidden = false;
    box.textContent = "";
    box.appendChild(el("p", { cls: "kicker", text: (r.record_type === "signal" ? "Emerging security signal" : "Global intelligence assessment") + " · " + r.id }));
    box.appendChild(el("h1", { cls: "doc-title", text: r.title }));
    box.appendChild(el("p", { cls: "doc-meta" }, [el("strong", { text: r.location || r.countries.join(", ") }), " | " + r.regions.join(", ") + " | Last verified " + fmt(r.last_verified, true) + "."]));

    var ident = [
      ["Threat ID", r.id], ["Location", r.location || "—"], ["Countries", r.countries.join(", ")],
      ["Regions", r.regions.join(", ")],
      ["Categories", r.primary_category + (r.secondary_categories.length ? " (also " + r.secondary_categories.join(", ") + ")" : "")],
      ["Priority", PRI_LABEL[r.priority]], ["Evidence status", r.evidence_status], ["Trend", r.trend],
      ["Event date", fmt(r.event_date)], ["First published", fmt(r.published_at, true)],
      ["Last verified", fmt(r.last_verified, true)], ["Last substantive update", fmt(r.last_substantive_update, true)],
      ["Independent sources", String(r.independent_sources)],
      ["Editorial approval", r.approved ? "Approved by " + r.approved_by + ", " + fmt(r.approved_at, true) : "Not required at this priority / evidence level"]
    ];
    box.appendChild(el("div", { cls: "doc-tbl-wrap" }, [el("table", { cls: "doc-tbl cols-2" }, [
      el("thead", null, [el("tr", null, [el("th", { scope: "col", text: "Identification" }), el("th", { scope: "col", text: "Value" })])]),
      el("tbody", null, ident.map(function (x) {
        var v = x[0] === "Priority" ? el("span", { cls: "pri " + r.priority, text: x[1] }) :
                x[0] === "Evidence status" ? el("span", { cls: "evi " + r.evidence_status.replace(/\s/g, ""), text: x[1] }) : x[1];
        return el("tr", null, [el("th", { scope: "row", text: x[0] }), el("td", null, [v])]);
      }))
    ])]));

    var n = 0;
    function h(t) { n += 1; return n + ". " + t; }
    box.appendChild(section(h("Executive Summary"), [el("p", { text: r.summary })]));
    if (r.record_type === "signal") {
      box.appendChild(section(h("Observed Action and Interpretation"), [
        el("div", { cls: "gi-block fact" }, [el("span", { cls: "lbl", text: "Observed action" }), el("p", { text: r.observed_action })]),
        el("div", { cls: "gi-block aegis" }, [el("span", { cls: "lbl", text: "AEGIS interpretation (analysis, not fact)" }), el("p", { text: r.interpretation })])
      ]));
    }
    box.appendChild(section(h("Confirmed Facts"), r.confirmed_facts.length ? r.confirmed_facts.map(function (c) { return block("fact", "Confirmed fact", c); })
      : [el("p", { text: "No facts are confirmed to AEGIS's standard yet. Everything below is attributed reporting or analysis." })]));
    box.appendChild(section(h("Reported Allegations"), r.reported_claims.length ? r.reported_claims.map(function (c) { return block("claim", "Unverified claim", c); })
      : [el("p", { text: "No unverified allegations are recorded." })]));
    if (r.international_perspectives.length) {
      box.appendChild(section(h("International Perspectives"), r.international_perspectives.map(function (c) { return block("persp", "Perspective", c); })));
    }
    box.appendChild(section(h("Impact"), [el("p", { text: r.impact_assessment })]));
    var aegis = [el("div", { cls: "gi-block aegis" }, [el("span", { cls: "lbl", text: "AEGIS assessment · priority rationale" }), el("p", { text: r.priority_rationale })])];
    if (r.unknowns.length) { aegis.push(el("p", null, [el("strong", { text: "Uncertainties and unknowns" })])); aegis.push(list(r.unknowns)); }
    if (r.reassessment_triggers.length) { aegis.push(el("p", null, [el("strong", { text: "Triggers for reassessment" })])); aegis.push(list(r.reassessment_triggers)); }
    box.appendChild(section(h("AEGIS Assessment"), aegis));
    box.appendChild(section(h("Monitoring Actions"), [list(r.monitoring_actions)]));
    if (r.threatwatch_cves.length) {
      box.appendChild(section(h("ThreatWatch Cross-References"), [
        el("p", { text: "Technical vulnerability details, exploitation status and remediation for related CVEs are in ThreatWatch:" }),
        el("ul", { cls: "gi-list" }, r.threatwatch_cves.map(function (c) {
          return el("li", null, [el("a", { href: "../threatwatch/validate.html?cve=" + encodeURIComponent(c), text: c })]);
        }))]));
    }
    box.appendChild(section(h("Sources"), [el("ol", { cls: "gi-list gi-src" }, r.sources.map(function (s) {
      var meta = [s.type.replace("_", " "), "published " + fmt(s.published), "accessed " + fmt(s.accessed)];
      if (s.region) meta.push(s.region + " reporting");
      if (s.state_affiliated) meta.push("state-affiliated");
      if (s.syndicated_from) meta.push("republished from " + s.syndicated_from + " (not independent)");
      return el("li", null, [el("strong", { text: s.publisher }), " — ", ext(s.url, s.title), el("span", { cls: "m", text: meta.join(" · ") })]);
    }))]));
    box.appendChild(section(h("Update History"), [el("div", { cls: "doc-tbl-wrap" }, [el("table", { cls: "doc-tbl cols-3" }, [
      el("thead", null, [el("tr", null, [el("th", { scope: "col", text: "Date" }), el("th", { scope: "col", text: "Change" }), el("th", { scope: "col", text: "Details" })])]),
      el("tbody", null, r.update_history.slice().reverse().map(function (u) {
        return el("tr", null, [el("th", { scope: "row", text: fmt(u.date, true) }), el("td", { text: HIST_LABEL[u.type] || u.type }), el("td", { text: u.summary })]);
      }))
    ])]), el("p", { cls: "gi-sub", text: "Earlier entries and corrections are preserved; nothing is silently overwritten." })]));
    box.appendChild(el("footer", { cls: "doc-foot" }, [el("span", { text: "AEGIS Global Intelligence | " + r.id }), el("a", { href: "../", text: "Back to dashboard" })]));
  }
})();
