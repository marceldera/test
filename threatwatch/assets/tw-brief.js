/* Aegis ThreatWatch — daily brief renderer.
 * All feed-derived text is inserted with textContent; links must be https.
 * No innerHTML is used with data.
 */
(function () {
  "use strict";
  var STALE_HOURS = 30;

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k];
      else if (k === "cls") n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) {
      if (c == null || c === false) return;
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  }
  function safeHref(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null; }
  function link(u, label) {
    var h = safeHref(u);
    return h ? el("a", { href: h, rel: "noopener noreferrer", text: label || h }) : document.createTextNode(label || "");
  }
  function unknown(v, fmt) { return v == null || v === "" ? "Unknown" : (fmt ? fmt(v) : String(v)); }
  function fmtTime(iso) {
    try {
      return new Date(iso).toLocaleString("en-US", { timeZone: "America/New_York", dateStyle: "medium", timeStyle: "short" }) + " ET";
    } catch (e) { return iso; }
  }
  function badge(p) {
    var labels = { emergency: "Emergency", urgent: "Urgent", routine: "Routine", monitor: "Monitor" };
    return el("span", { cls: "badge b-" + (labels[p] ? p : "neutral"), text: labels[p] || p });
  }
  function h2(num, text, id) { return el("h2", { id: id }, [el("span", { cls: "num", text: String(num).padStart(2, "0") }), text]); }
  function getJSON(url) {
    return fetch(url, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); });
  }
  function pct(v) { return (v * 100).toFixed(1) + "%"; }

  // ------------------------------------------------------------------ report (framed document)
  var CVE_RE = /(CVE-\d{4}-\d{4,7})/g;
  // Text → nodes: **bold** runs become <strong>, CVE ids link to the validation page. No HTML is parsed.
  function rich(text, linkCves) {
    var out = [];
    String(text).split("**").forEach(function (part, i) {
      if (!part) return;
      var kids = [];
      part.split(CVE_RE).forEach(function (bit, j) {
        if (!bit) return;
        if (j % 2 === 1 && linkCves) kids.push(el("a", { cls: "cve-link", href: "validate.html?cve=" + encodeURIComponent(bit), text: bit }));
        else kids.push(document.createTextNode(bit));
      });
      out.push(i % 2 === 1 ? el("strong", null, kids) : el("span", null, kids));
    });
    return out;
  }
  function block(b) {
    if (b.type === "p") return el("p", null, rich(b.text, true));
    if (b.type === "table") {
      var cls = "doc-tbl cols-" + b.columns.length;
      return el("div", { cls: "doc-tbl-wrap" }, [el("table", { cls: cls }, [
        el("thead", null, [el("tr", null, b.columns.map(function (c) { return el("th", { scope: "col", text: c }); }))]),
        el("tbody", null, b.rows.map(function (r) {
          return el("tr", null, r.map(function (cell, i) {
            return i === 0 ? el("th", { scope: "row" }, rich(cell, true)) : el("td", null, rich(cell, true));
          }));
        }))
      ])]);
    }
    return null;
  }
  function renderReport(r, body) {
    var paper = el("article", { cls: "paper", "aria-labelledby": "doc-title" }, [
      el("h1", { id: "doc-title", cls: "doc-title" }, r.title.map(function (line, i) {
        return el("span", { text: line });
      })),
      el("p", { cls: "doc-meta" }, [el("strong", { text: r.dateLabel }), " | " + r.window + " | " + r.prepared + "."]),
      el("p", { cls: "doc-note" }, [el("strong", { text: "Source note: " }), r.sourceNote])
    ]);
    r.sections.forEach(function (s) {
      var sec = el("section", { cls: "doc-sec", "aria-labelledby": "doc-s" + s.num }, [
        el("h2", { id: "doc-s" + s.num, text: s.num + ". " + s.title })
      ]);
      s.blocks.forEach(function (bl) { var n = block(bl); if (n) sec.appendChild(n); });
      paper.appendChild(sec);
    });
    if (r.references && r.references.length) {
      paper.appendChild(el("section", { cls: "doc-sec doc-refs", "aria-labelledby": "doc-refs" }, [
        el("h2", { id: "doc-refs", text: "Primary Public References" })
      ].concat(r.references.map(function (ref) {
        return el("p", null, [ref.label + ": ", link(ref.url)]);
      }))));
    }
    paper.appendChild(el("footer", { cls: "doc-foot" }, [
      el("span", { text: r.footer }),
      el("span", { text: "Aegis Cyber Solutions · ThreatWatch" })
    ]));
    body.appendChild(paper);
  }

  var DAY_MS = 864e5;
  function isoDay(t) { return new Date(t).toISOString().slice(0, 10); }
  function printButton() {
    var btn = el("button", { type: "button", cls: "btn-print", text: "Print / Save as PDF" });
    btn.addEventListener("click", function () { window.print(); });
    return btn;
  }
  // Last 7 calendar days ending at the newest edition; days without an edition are shown disabled.
  function renderToolbar(b, status, editions) {
    var bar = document.getElementById("brief-toolbar");
    bar.textContent = "";
    var have = {};
    (editions || []).forEach(function (e) { have[e.edition] = true; });
    have[b.edition] = true;
    var newest = (editions && editions.length ? editions[0].edition : b.edition);
    var end = Date.parse(newest + "T12:00:00Z");
    var strip = el("div", { cls: "day-strip", role: "group", "aria-label": "Editions from the last 7 days" });
    for (var i = 6; i >= 0; i--) {
      (function (day) {
        var d = new Date(Date.parse(day + "T12:00:00Z"));
        var wk = d.toLocaleDateString("en-US", { weekday: "short", timeZone: "UTC" });
        var md = d.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
        var on = day === b.edition;
        var btn = el("button", { type: "button", cls: "day" + (on ? " on" : ""), "aria-pressed": on ? "true" : "false",
          title: have[day] ? "Edition of " + md : "No edition published for " + md }, [el("span", { cls: "wk", text: wk }), el("span", { cls: "md", text: md })]);
        if (!have[day]) btn.disabled = true;
        else btn.addEventListener("click", function () {
          if (day === b.edition) return;
          getJSON("data/briefs/" + day + ".json").then(function (nb) { renderBrief(nb, status, editions); window.scrollTo(0, 0); })
            .catch(function () { document.getElementById("notices").appendChild(el("p", { cls: "notice", text: "That edition could not be loaded." })); });
        });
        strip.appendChild(btn);
      })(isoDay(end - i * DAY_MS));
    }
    bar.appendChild(strip);
    bar.appendChild(printButton());
  }

  // ------------------------------------------------------------------ brief
  function renderBrief(b, status, editions) {
    if (!window.__twNewest) window.__twNewest = (editions && editions.length) ? editions[0].edition : b.edition;
    var body = document.getElementById("brief-body");
    if (b.report && b.report.sections) {
      body.textContent = "";
      document.getElementById("brief-title").textContent = "Daily Threat Intelligence Brief — " +
        new Date(b.edition + "T12:00:00Z").toLocaleDateString("en-US", { dateStyle: "long", timeZone: "UTC" });
      document.getElementById("brief-meta").textContent = "Published " + fmtTime(b.publishedAt) +
        " · a new edition is issued every morning at 7:00 AM ET";
      freshness(b, status);
      renderToolbar(b, status, editions);
      renderReport(b.report, body);
      return;
    }
    legacyBrief(b, status);
  }

  function freshness(b, status) {
    var age = (Date.now() - Date.parse(b.publishedAt)) / 36e5;
    var fresh = document.getElementById("freshness");
    fresh.textContent = "";
    var latest = !window.__twNewest || b.edition === window.__twNewest;
    var stale = age > STALE_HOURS && latest;
    fresh.appendChild(el("span", { cls: "fresh" + (stale ? " stale" : "") }, [
      el("span", { cls: "badge " + (stale ? "b-urgent" : "b-ok"), text: stale ? "Stale" : (latest ? "Current" : "Archive") }),
      stale ? "This edition is " + Math.round(age) + " hours old; a newer edition has not been published."
            : "Last successful refresh " + fmtTime((status && status.lastSuccessAt) || b.publishedAt)
    ]));
    var notices = document.getElementById("notices");
    notices.textContent = "";
    if (status && status.ok === false) {
      notices.appendChild(el("p", { cls: "notice", text: "The most recent refresh attempt (" + fmtTime(status.lastAttemptAt) +
        ") did not pass quality checks. The last verified edition is shown." }));
    }
  }

  function legacyBrief(b, status) {
    var body = document.getElementById("brief-body");
    body.textContent = "";
    document.getElementById("brief-title").textContent = "Zero-Day Intelligence Brief — " +
      new Date(b.edition + "T12:00:00Z").toLocaleDateString("en-US", { dateStyle: "long", timeZone: "UTC" });
    document.getElementById("brief-meta").textContent = "Published " + fmtTime(b.publishedAt) +
      " · Window " + fmtTime(b.window.start) + " → " + fmtTime(b.window.end);

    var age = (Date.now() - Date.parse(b.publishedAt)) / 36e5;
    var fresh = document.getElementById("freshness");
    fresh.textContent = "";
    var stale = age > STALE_HOURS;
    fresh.appendChild(el("span", { cls: "fresh" + (stale ? " stale" : "") }, [
      el("span", { cls: "badge " + (stale ? "b-urgent" : "b-ok"), text: stale ? "Stale" : "Current" }),
      stale ? "This edition is " + Math.round(age) + " hours old; a newer edition has not been published."
            : "Last successful refresh " + fmtTime((status && status.lastSuccessAt) || b.publishedAt)
    ]));
    var notices = document.getElementById("notices");
    if (status && status.ok === false) {
      notices.appendChild(el("p", { cls: "notice", text: "The most recent refresh attempt (" + fmtTime(status.lastAttemptAt) +
        ") did not pass quality checks. The last verified edition is shown." }));
    }

    var c = b.executive.counts;
    // 1. Executive summary
    body.appendChild(el("section", { "aria-labelledby": "s1" }, [
      h2(1, "Executive Intelligence Summary", "s1"),
      el("p", { cls: "summary", text: b.executive.summary }),
      el("ul", { cls: "counts", "aria-label": "Verified counts" }, [
        el("li", null, [el("b", { text: String(c.kevAdded) }), "new KEV entries"]),
        el("li", null, [el("b", { text: String(c.emergency) }), "emergency"]),
        el("li", null, [el("b", { text: String(c.urgent) }), "urgent"]),
        el("li", null, [el("b", { text: String(c.criticalHigh) }), "critical/high CVSS"]),
        el("li", null, [el("b", { text: String(c.kevRansomware) }), "ransomware-linked"]),
        el("li", null, [el("b", { text: String(c.materialChanges) }), "other material changes"])
      ]),
      b.executive.developments.length ? el("h3", { text: "Top developments" }) : null,
      b.executive.developments.length ? el("ul", { cls: "plain" }, b.executive.developments.map(function (d) { return el("li", { text: d }); })) : null
    ]));

    // 2. Top actions
    var s2 = el("section", { "aria-labelledby": "s2" }, [h2(2, "Top Actions", "s2")]);
    if (!b.actions.length) s2.appendChild(el("p", { cls: "muted", text: "No emergency or urgent actions are justified by today’s verified data." }));
    else s2.appendChild(el("ol", { cls: "actions" }, b.actions.map(function (a) {
      return el("li", null, [
        el("h3", null, [badge(a.priority), " ", a.title]),
        el("p", { cls: "muted", text: a.why }),
        el("ul", null, a.steps.map(function (s) { return el("li", { text: s }); })),
        el("div", { cls: "srcs" }, ["Evidence: "].concat(a.evidence.map(function (u, i) { return link(u, "source " + (i + 1)); })))
      ]);
    })));
    body.appendChild(s2);

    // 3. CVEs
    var s3 = el("section", { "aria-labelledby": "s3" }, [h2(3, "Critical CVEs & Zero-Days", "s3")]);
    if (!b.cves.length) s3.appendChild(el("p", { cls: "muted", text: "No newly confirmed exploited vulnerabilities in this window." }));
    b.cves.forEach(function (v) { s3.appendChild(cveCard(v)); });
    if (b.overflow) s3.appendChild(el("p", { cls: "muted" }, [b.overflow + " additional additions are listed only in the ",
      link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV catalog"), "."]));
    body.appendChild(s3);

    // 4–6 editorial sections
    body.appendChild(editorialSection(4, "Active Exploitation and Campaigns", b.campaigns));
    body.appendChild(editorialSection(5, "Industry & Geographic Market Impact", b.industries));
    body.appendChild(editorialSection(6, "Threat Actor Intelligence", b.actors));

    // 7. Remediation
    var g = b.remediation.groups, guide = b.remediation.guidance;
    var rows = ["emergency", "urgent", "routine", "monitor"].map(function (k) {
      return el("tr", null, [el("th", { scope: "row" }, [badge(k)]),
        el("td", { cls: "mono", text: g[k].length ? g[k].join(", ") : "None" }),
        el("td", { text: guide[k] })]);
    });
    body.appendChild(el("section", { "aria-labelledby": "s7" }, [h2(7, "Risk-Based Remediation", "s7"),
      el("div", { cls: "tbl-wrap" }, [el("table", null, [
        el("caption", { text: "Suggested response windows are guidance, not universal policy." }),
        el("thead", null, [el("tr", null, [el("th", { scope: "col", text: "Tier" }), el("th", { scope: "col", text: "CVEs" }), el("th", { scope: "col", text: "Guidance" })])]),
        el("tbody", null, rows)])])]));

    // 8. Changes
    var s8 = el("section", { "aria-labelledby": "s8" }, [h2(8, "What Changed Since Yesterday", "s8")]);
    s8.appendChild(b.changes.length ? el("ul", { cls: "plain" }, b.changes.map(function (ch) {
      return el("li", null, [el("span", { cls: "mono", text: ch.cve }), " — " + ch.detail]);
    })) : el("p", { cls: "muted", text: "No material changes since the previous edition." }));
    body.appendChild(s8);

    // 9. Sources & confidence
    var cov = b.coverage;
    body.appendChild(el("section", { "aria-labelledby": "s9" }, [h2(9, "Sources & Confidence", "s9"),
      el("ul", { cls: "plain" }, b.sources.map(function (s) {
        return el("li", null, [link(s.url, s.name), " — " + [s.version ? "version " + s.version : null,
          s.fetchedAt ? "fetched " + fmtTime(s.fetchedAt) : null, s.status, s.note].filter(Boolean).join(" · ")]);
      })),
      el("p", null, [el("strong", { text: "Covered: " }), cov.covered.join("; ") + "."]),
      cov.notCovered.length ? el("p", null, [el("strong", { text: "Not covered today: " }), cov.notCovered.join("; ") + "."]) : null,
      cov.unknownFields.length ? el("p", null, [el("strong", { text: "Fields shown as Unknown: " }), cov.unknownFields.join(", ") + "."]) : null,
      el("p", { cls: "muted", text: cov.editorial.present ? "Editorial review: " + cov.editorial.reviewedBy + ", " + fmtTime(cov.editorial.reviewedAt) + "."
        : "No analyst editorial review was applied to this edition; it is fully automated from the sources above." })
    ]));
  }

  function cveCard(v) {
    var cv = v.cvss, ep = v.epss;
    var facts = [
      ["Product", v.vendor + " " + v.product],
      ["Exploitation", v.exploitation.status + ". " + v.exploitation.basis],
      ["Exploit maturity", unknown(v.exploitMaturity)],
      ["CVSS", cv ? cv.score + " " + (cv.severity || "") + " (v" + cv.version + ")" : "Unknown"],
      ["Vector", cv ? unknown(cv.vector) : "Unknown"],
      ["Attack / auth / UI", cv ? [unknown(cv.attackVector), "privileges " + unknown(cv.privileges), "user interaction " + unknown(cv.userInteraction)].join(" · ") : "Unknown"],
      ["EPSS", ep ? pct(ep.score) + " probability · " + pct(ep.percentile) + " percentile · " + ep.date : "Unknown"],
      ["KEV", "Added " + v.kev.dateAdded + " · federal due date " + unknown(v.kev.dueDate) + " · ransomware use: " + v.kev.ransomware],
      ["Affected versions", unknown(v.affectedVersions)],
      ["Fixed versions", unknown(v.fixedVersions)],
      ["Patch / workaround", unknown(v.kev.requiredAction)]
    ];
    var dl = el("dl", { cls: "facts" });
    facts.forEach(function (f) { dl.appendChild(el("dt", { text: f[0] })); dl.appendChild(el("dd", { text: f[1] })); });
    return el("details", { cls: "cve" }, [
      el("summary", null, [
        el("span", { cls: "line1" }, [badge(v.priority), el("strong", { text: v.cve }), el("span", { text: v.vendor + " " + v.product })]),
        el("span", { cls: "line2", text: v.name + (cv ? " · CVSS " + cv.score : "") + (ep ? " · EPSS " + pct(ep.percentile) + " pct" : "") })
      ]),
      el("div", { cls: "cve-body" }, [
        v.description ? el("p", { text: v.description }) : null,
        el("div", { cls: "why" }, [el("strong", { text: "Why it matters: " }), v.rationale]),
        dl,
        el("div", { cls: "srcs" }, ["Sources: "].concat(v.sources.map(function (s) { return link(s.url, s.label); }))),
        el("p", null, [el("a", { href: "validate.html?cve=" + encodeURIComponent(v.cve), text: "Validation guidance for " + v.cve + " →" })])
      ])
    ]);
  }

  function editorialSection(n, title, sec) {
    var s = el("section", { "aria-labelledby": "s" + n }, [h2(n, title, "s" + n)]);
    if (!sec || sec.status !== "editorial" || !sec.items.length) {
      s.appendChild(el("p", { cls: "muted", text: (sec && sec.note) || "Not covered in this edition." }));
      return s;
    }
    sec.items.forEach(function (it) {
      var bits = [];
      if (it.aliases && it.aliases.length) bits.push("Aliases: " + it.aliases.join(", "));
      if (it.type) bits.push(it.type);
      if (it.motivation) bits.push("Motivation: " + it.motivation);
      if (it.sectors && it.sectors.length) bits.push("Sectors: " + it.sectors.join(", "));
      if (it.regions && it.regions.length) bits.push("Regions: " + it.regions.join(", "));
      if (it.cves && it.cves.length) bits.push("CVEs: " + it.cves.join(", "));
      if (it.techniques && it.techniques.length) bits.push("ATT&CK: " + it.techniques.join(", "));
      if (it.relation) bits.push(it.relation === "observed_targeting" ? "Observed targeting" : "Possible exposure");
      s.appendChild(el("div", { cls: "why" }, [
        el("h3", null, [it.name + " ", el("span", { cls: "badge b-neutral", text: it.confidence + " confidence" })]),
        it.summary ? el("p", { text: it.summary }) : null,
        bits.length ? el("p", { cls: "muted", text: bits.join(" · ") }) : null,
        el("div", { cls: "srcs" }, ["Sources: "].concat(it.sources.map(function (u, i) { return link(u, "source " + (i + 1)); })))
      ]));
    });
    return s;
  }

  // ------------------------------------------------------------------ monthly page
  function renderMonthly(index) {
    var body = document.getElementById("month-body");
    var bar = document.getElementById("month-toolbar");
    body.textContent = ""; bar.textContent = "";
    if (!index || !index.months || !index.months.length) {
      document.getElementById("month-meta").textContent = "";
      body.appendChild(el("p", { cls: "notice", text: "The monthly summary will appear after the first edition is published." }));
      return;
    }
    var strip = el("div", { cls: "day-strip", role: "group", "aria-label": "Monthly summaries" });
    var buttons = {};
    index.months.slice().reverse().forEach(function (m) {
      var d = new Date(m.month + "-15T12:00:00Z");
      var btn = el("button", { type: "button", cls: "day", "aria-pressed": "false" }, [
        el("span", { cls: "wk", text: d.toLocaleDateString("en-US", { year: "numeric", timeZone: "UTC" }) }),
        el("span", { cls: "md", text: d.toLocaleDateString("en-US", { month: "short", timeZone: "UTC" }) + (m.complete ? "" : " · MTD") })]);
      btn.addEventListener("click", function () { load(m.month); });
      buttons[m.month] = btn;
      strip.appendChild(btn);
    });
    bar.appendChild(strip);
    bar.appendChild(printButton());
    function load(m) {
      if (!/^\d{4}-\d{2}$/.test(m)) return;
      Object.keys(buttons).forEach(function (k) {
        buttons[k].classList.toggle("on", k === m);
        buttons[k].setAttribute("aria-pressed", k === m ? "true" : "false");
      });
      getJSON("data/monthly/" + m + ".json").then(function (d) {
        body.textContent = "";
        document.getElementById("month-title").textContent = "Monthly Threat Intelligence Summary — " + monthName(d.month);
        document.getElementById("month-meta").textContent = (d.complete ? "Final summary" : "Month to date") +
          " · updated " + fmtTime(d.updatedAt) + " · refreshed every morning at 7:00 AM ET";
        if (d.report && d.report.sections) renderReport(d.report, body);
        else body.appendChild(monthCard(d));
      }).catch(function () { body.textContent = ""; body.appendChild(el("p", { cls: "notice", text: "Monthly data unavailable." })); });
    }
    var want = (location.hash || "").replace("#", "");
    load(buttons[want] ? want : index.months[0].month);
  }
  function monthName(m) { return new Date(m + "-15T12:00:00Z").toLocaleDateString("en-US", { month: "long", year: "numeric", timeZone: "UTC" }); }

  function monthCard(d) {
    var rows = d.events.map(function (e) {
      return el("tr", null, [el("td", { cls: "mono", text: e.date }), el("td", { cls: "mono" }, [el("a", { href: "validate.html?cve=" + encodeURIComponent(e.cve), text: e.cve })]),
        el("td", { text: e.vendor + " " + e.product }), el("td", { text: e.concern + (e.ransomware === "known" ? " (ransomware use known)" : "") }),
        el("td", { text: e.confidence }), el("td", null, [link(e.source, "CISA KEV")])]);
    });
    return el("details", { cls: "monthly" }, [
      el("summary", null, [el("span", { text: monthName(d.month) + (d.complete ? "" : " — month to date") }), el("span", { cls: "hint", text: "Expand chronology ▾" })]),
      el("div", { cls: "metrics", role: "list" }, d.metrics.map(function (m) {
        return el("div", { cls: "metric", role: "listitem", title: m.rule + " Source: " + m.source + ". Window: " + m.window + "." },
          [el("b", { text: String(m.value) }), el("span", { text: m.label })]);
      })),
      el("div", { cls: "monthly-body" }, [
        el("p", { cls: "muted", text: d.notice + " Updated " + fmtTime(d.updatedAt) + "." }),
        el("ul", { cls: "plain muted" }, d.metrics.map(function (m) { return el("li", { text: m.label + ": " + m.rule + " Source: " + m.source + "." }); })),
        rows.length ? el("div", { cls: "tbl-wrap" }, [el("table", null, [
          el("caption", { text: "Notable entries in chronological order" }),
          el("thead", null, [el("tr", null, ["Date", "CVE", "Vendor / product", "Operational concern", "Confidence", "Source"].map(function (h) { return el("th", { scope: "col", text: h }); }))]),
          el("tbody", null, rows)])]) : el("p", { text: "No KEV additions recorded for this month yet." })
      ])
    ]);
  }

  // ------------------------------------------------------------------ boot
  if (document.getElementById("month-body")) {
    getJSON("data/monthly/index.json").then(renderMonthly).catch(function () { renderMonthly(null); });
    return;
  }
  var statusP = getJSON("data/status.json").catch(function () { return null; });
  var editionsP = getJSON("data/briefs/index.json").then(function (d) { return d.editions || []; }).catch(function () { return []; });
  Promise.all([getJSON("data/latest.json"), statusP, editionsP]).then(function (r) { renderBrief(r[0], r[1], r[2]); })
    .catch(function () {
      document.getElementById("brief-meta").textContent = "";
      document.getElementById("brief-body").appendChild(el("p", { cls: "notice",
        text: "The daily brief is temporarily unavailable. No edition has passed verification yet, or the data could not be loaded. Please check back shortly." }));
    });
})();
