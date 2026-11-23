/* AEGIS Global Threat Intelligence dashboard. Reads only the generated JSON in ./data; renders with
   textContent (never innerHTML) so record text can never inject markup. */
(function () {
  "use strict";
  var PRI = ["CRITICAL", "HIGH", "MODERATE", "LOW"];
  var PRI_LABEL = { CRITICAL: "Critical", HIGH: "High", MODERATE: "Moderate", LOW: "Low" };
  var REGIONS = ["Africa", "Asia-Pacific", "Europe", "Middle East", "North America", "Latin America", "Global"];
  var CATS = ["Geopolitical", "Military", "Cybersecurity", "AI", "Critical Infrastructure", "Humanitarian", "Environmental"];
  var EVID = ["Confirmed", "Reported", "Disputed", "Analytical Assessment"];
  var PERIODS = [["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["all", "Historical (all)"]];
  var $ = function (id) { return document.getElementById(id); };
  // The dashboard is served at the site root (data-gi-base="global-intelligence/") and can also run inside its folder.
  var BASE = document.body.getAttribute("data-gi-base") || "";
  if (!/^([a-z\-]+\/)?$/.test(BASE)) BASE = "";

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
  function getJSON(u) {
    return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(u + " " + r.status); return r.json(); });
  }
  function fmt(ts, withTime) {
    if (!ts) return "—";
    var d = new Date(ts.length === 10 ? ts + "T12:00:00Z" : ts);
    if (isNaN(d)) return "—";
    var o = { month: "short", day: "numeric", year: "numeric", timeZone: "America/New_York" };
    if (withTime) { o.hour = "numeric"; o.minute = "2-digit"; o.timeZoneName = "short"; }
    if (ts.length === 10) o.timeZone = "UTC";
    return d.toLocaleString("en-US", o);
  }
  function pri(p) { return el("span", { cls: "pri " + p, text: PRI_LABEL[p] || p }); }
  function evi(e) { return el("span", { cls: "evi " + e.replace(/\s/g, ""), text: e }); }
  function trend(t) { return el("span", { cls: "trend " + t, text: t }); }

  var state = { records: [], historical: [], now: Date.now() };

  // ---------------------------------------------------------------- header
  function renderHeader(sum, upd) {
    var c = sum.counts;
    var m = $("gi-metrics");
    m.textContent = "";
    [["Reporting date", fmt(upd.reporting_date), ""], ["Active events", c.active, ""], ["Critical", c.critical, "crit"],
     ["High priority", c.high, "high"], ["Countries affected", c.countries, ""], ["Updated in 24 h", c.updated_24h, ""]]
      .forEach(function (x) {
        m.appendChild(el("div", { cls: "gi-metric " + x[2] }, [el("span", { cls: "v", text: String(x[1]) }), el("span", { cls: "l", text: x[0] })]));
      });
    var t = $("gi-times");
    t.textContent = "";
    t.appendChild(document.createTextNode("Collected "));
    t.appendChild(el("b", { text: fmt(upd.collected_at, true) }));
    t.appendChild(document.createTextNode(" · Last editorial verification "));
    t.appendChild(el("b", { text: fmt(upd.last_verified, true) }));
    t.appendChild(document.createTextNode(" · " + (upd.cadence || "")));
    if (upd.demo) $("gi-demo").hidden = false;
    // executive summary: first paragraph visible, the rest expandable
    var paras = String(sum.summary || "").split(/\n\n+/);
    var box = $("gi-summary-body");
    box.textContent = "";
    box.appendChild(el("p", { text: paras[0] || "" }));
    if (paras.length > 1) {
      var det = el("details", null, [el("summary", { text: "Read the full executive summary (" + sum.word_count + " words)" })]);
      paras.slice(1).forEach(function (p) { det.appendChild(el("p", { text: p })); });
      box.appendChild(det);
    }
    $("gi-summary-meta").textContent = "Generated " + fmt(sum.generated_at, true) + " from published records only.";
  }

  // ---------------------------------------------------------------- filters
  function chips(container, name, values, labels) {
    var box = $(container);
    values.forEach(function (v) {
      var id = name + "-" + v.replace(/[^A-Za-z0-9]/g, "");
      box.appendChild(el("label", { cls: "gi-chip", "for": id }, [
        el("input", { type: "checkbox", id: id, name: name, value: v }),
        el("span", { text: labels ? labels[v] : v })]));
    });
  }
  function checked(name) {
    return Array.prototype.slice.call(document.querySelectorAll("input[name=" + name + "]:checked")).map(function (i) { return i.value; });
  }
  function readURL() {
    var q = new URLSearchParams(location.search);
    ["region", "category", "priority", "evidence"].forEach(function (n) {
      (q.get(n) || "").split(",").filter(Boolean).forEach(function (v) {
        var i = document.querySelector("input[name=" + n + "][value='" + v.replace(/'/g, "") + "']");
        if (i) i.checked = true;
      });
    });
    if (q.get("q")) $("f-q").value = q.get("q").slice(0, 100);
    if (q.get("country")) $("f-q").value = q.get("country").slice(0, 100);
  }

  // Default: the shortest period that still shows every active event (based on latest substantive update).
  function defaultPeriod(recs) {
    var now = state.now;
    if (!recs.length) return "all";
    for (var i = 0; i < 3; i++) {
      var days = +PERIODS[i][0];
      if (recs.every(function (r) { return now - Date.parse(r.last_substantive_update) <= days * 864e5; })) return PERIODS[i][0];
    }
    return "all";
  }

  function apply() {
    var regions = checked("region"), cats = checked("category"), pris = checked("priority"), evs = checked("evidence");
    var period = $("f-period").value, view = $("f-view").value, q = $("f-q").value.trim().toLowerCase();
    var from = $("f-from").value, to = $("f-to").value, sort = $("f-sort").value;
    var pool = view === "active" ? state.records : view === "resolved" ? state.historical : state.records.concat(state.historical);
    var rows = pool.filter(function (r) {
      if (regions.length && !r.regions.some(function (g) { return regions.indexOf(g) >= 0; })) return false;
      if (cats.length && cats.indexOf(r.primary_category) < 0 &&
          !r.secondary_categories.some(function (c) { return cats.indexOf(c) >= 0; })) return false;
      if (pris.length && pris.indexOf(r.priority) < 0) return false;
      if (evs.length && evs.indexOf(r.evidence_status) < 0) return false;
      // period = latest substantive update, so older events with a new material update still show
      if (period !== "all" && state.now - Date.parse(r.last_substantive_update) > (+period) * 864e5) return false;
      if (from && r.event_date < from) return false;
      if (to && r.event_date > to) return false;
      if (q) {
        var hay = [r.id, r.title, r.location, r.summary].concat(r.countries, r.regions).join(" ").toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
    rows.sort(function (a, b) {
      if (sort === "date") return b.last_substantive_update.localeCompare(a.last_substantive_update);
      if (sort === "country") return a.countries[0].localeCompare(b.countries[0]) || PRI.indexOf(a.priority) - PRI.indexOf(b.priority);
      if (sort === "event") return b.event_date.localeCompare(a.event_date);
      return PRI.indexOf(a.priority) - PRI.indexOf(b.priority) || b.last_substantive_update.localeCompare(a.last_substantive_update);
    });
    renderMatrix(rows, pool.length);
    var p = new URLSearchParams();
    [["region", regions], ["category", cats], ["priority", pris], ["evidence", evs]].forEach(function (x) { if (x[1].length) p.set(x[0], x[1].join(",")); });
    if (q) p.set("q", q);
    history.replaceState(null, "", location.pathname + (p.toString() ? "?" + p : "") + location.hash);
  }

  function renderMatrix(rows, total) {
    var tb = $("gi-rows");
    tb.textContent = "";
    $("gi-count").textContent = rows.length + " of " + total + " event" + (total === 1 ? "" : "s") + " shown.";
    if (!rows.length) {
      tb.appendChild(el("tr", null, [el("td", { colspan: "8", cls: "gi-empty", text: "No events match these filters. Try a longer period or reset the filters." })]));
      return;
    }
    rows.forEach(function (r) {
      var href = BASE + "assessment.html?id=" + encodeURIComponent(r.id);
      tb.appendChild(el("tr", { cls: r.priority === "CRITICAL" ? "row-crit" : r.priority === "HIGH" ? "row-high" : "" }, [
        el("th", { scope: "row", cls: "gid" }, [r.demo ? el("span", { cls: "demo-tag", text: "Demo" }) : null, r.demo ? el("br") : null, r.id]),
        el("td", { "data-label": "Region" }, [r.regions.join(", "), el("span", { cls: "sm", text: r.countries.join(", ") })]),
        el("td", { "data-label": "Threat" }, [el("span", { cls: "ttl", text: r.title })]),
        el("td", { "data-label": "Category / priority" }, [r.primary_category, el("br"), pri(r.priority)]),
        el("td", { "data-label": "Evidence" }, [evi(r.evidence_status)]),
        el("td", { "data-label": "Dates" }, ["Event " + fmt(r.event_date), el("span", { cls: "sm", text: "Verified " + fmt(r.last_verified) })]),
        el("td", { "data-label": "Trend" }, [trend(r.trend)]),
        el("td", null, [el("a", { cls: "open", href: href, "aria-label": "Open assessment " + r.id + ": " + r.title, text: "Open →" })])
      ]));
    });
  }

  // ---------------------------------------------------------------- signals + charts
  function renderSignals(sigs) {
    var box = $("gi-signals");
    box.textContent = "";
    if (!sigs.length) { box.appendChild(el("p", { text: "No emerging signals are currently published." })); return; }
    sigs.forEach(function (s) {
      box.appendChild(el("article", { cls: "gi-signal" }, [
        el("div", null, [s.demo ? el("span", { cls: "demo-tag", text: "Demo" }) : null, pri(s.priority), " ", evi(s.evidence_status)]),
        el("h3", { text: s.title }),
        el("div", { cls: "obs" }, [el("span", { cls: "lbl", text: "Observed action" }), el("p", { text: s.observed_action })]),
        el("div", { cls: "int" }, [el("span", { cls: "lbl", text: "AEGIS interpretation" }), el("p", { text: s.interpretation })]),
        el("div", { cls: "meta" }, [s.countries.join(", ") + " · " + fmt(s.event_date) + " · ",
          el("a", { href: BASE + "assessment.html?id=" + encodeURIComponent(s.id), text: "Details" })])
      ]));
    });
  }
  function renderCharts(dist) {
    var box = $("gi-charts");
    box.textContent = "";
    [["By region", "region", REGIONS], ["By primary category", "category", CATS], ["By priority", "priority", PRI],
     ["By evidence status", "evidence", EVID]].forEach(function (c) {
      var data = dist[c[1]] || {};
      var max = Math.max.apply(null, c[2].map(function (k) { return data[k] || 0; }).concat([1]));
      var fig = el("figure", { cls: "gi-chart", "aria-label": c[0] }, [el("h3", { text: c[0] })]);
      c[2].forEach(function (k) {
        var n = data[k] || 0;
        var fill = el("span", { cls: "fill" });
        fill.style.width = (100 * n / max) + "%";
        fig.appendChild(el("div", { cls: "gi-bar" }, [el("span", { text: PRI_LABEL[k] || k }), el("span", { cls: "track", "aria-hidden": "true" }, [fill]), el("span", { cls: "n", text: String(n) })]));
      });
      box.appendChild(fig);
    });
  }

  // ---------------------------------------------------------------- boot
  chips("f-region", "region", REGIONS);
  chips("f-category", "category", CATS);
  chips("f-priority", "priority", PRI, PRI_LABEL);
  chips("f-evidence", "evidence", EVID);
  PERIODS.forEach(function (p) { $("f-period").appendChild(el("option", { value: p[0], text: p[1] })); });
  readURL();

  Promise.all([getJSON(BASE + "data/active-threats.json"), getJSON(BASE + "data/historical-threats.json"), getJSON(BASE + "data/signals.json"),
               getJSON(BASE + "data/executive-summary.json"), getJSON(BASE + "data/last-updated.json")])
    .then(function (d) {
      state.records = d[0].records || [];
      state.historical = (d[1].records || []).filter(function (r) { return r.record_type === "event"; });
      state.now = Date.parse(d[4].collected_at) || Date.now();
      renderHeader(d[3], d[4]);
      renderSignals(d[2].records || []);
      renderCharts(d[3].distribution || {});
      $("f-period").value = new URLSearchParams(location.search).get("period") || defaultPeriod(state.records);
      $("f-view").addEventListener("change", function () {
        if ($("f-view").value !== "active") $("f-period").value = "all";   // the archive is historical by definition
      });
      $("gi-filters").addEventListener("input", apply);
      $("gi-filters").addEventListener("change", apply);
      $("gi-filters").addEventListener("submit", function (e) { e.preventDefault(); });
      $("f-reset").addEventListener("click", function () {
        $("gi-filters").reset();
        $("f-period").value = defaultPeriod(state.records);
        apply();
      });
      apply();
    })
    .catch(function () {
      $("gi-rows").textContent = "";
      $("gi-count").textContent = "Intelligence data could not be loaded. Please try again later.";
    });
})();
