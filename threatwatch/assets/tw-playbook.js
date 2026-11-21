/* Aegis ThreatWatch — validation playbook builder (browser only; nothing is sent anywhere).
 * Combines: Aegis-curated CVE playbooks, the product library (read-only version checks),
 * public detection checks (Nuclei / Nmap NSE) and generic fallbacks.
 */
(function () {
  "use strict";
  var STAGES = [
    ["inventory", "1. Identify affected software and versions", "Authenticated, read-only. The most reliable evidence."],
    ["configuration", "2. Check the vulnerable configuration", "Is the feature or condition the CVE needs actually enabled?"],
    ["exposure", "3. Confirm network exposure", "Non-intrusive probes from where an attacker would be."],
    ["detection", "4. Detection checks and indicators", "Public checks and log indicators. Positive = suspected until confirmed."],
    ["mitigation", "5. Remediate or mitigate", "Apply the fix or an approved interim mitigation."],
    ["verification", "6. Verify remediation", "Re-run the same checks to prove the fix is live."]
  ];
  var PLATFORM = { linux: "Linux shell", windows: "PowerShell", macos: "macOS shell", kubernetes: "kubectl", container: "Docker",
    "appliance-cli": "Appliance CLI", "web-ui": "Admin UI", network: "From a scanning host" };

  function matchProduct(lib, vendor, product) {
    var key = vendor + ":" + product;
    for (var i = 0; i < lib.length; i++) {
      var ok = lib[i].cpe.some(function (c) {
        return c.slice(-1) === "*" ? key.indexOf(c.slice(0, -1)) === 0 : c === key;
      });
      if (ok) return lib[i];
    }
    return null;
  }

  function token(product) {
    var t = product.split(/[_\-]/).filter(function (x) { return x.length >= 3 && !/^(server|data|center|enterprise|platform|edition)$/.test(x); });
    return (t[0] || product).replace(/[^A-Za-z0-9.+]/g, "");
  }

  function genericChecks(a) {
    var t = token(a.product), part = a.part || (/(^|_)(linux|windows|os|ios|firmware|freebsd|macos)($|_)/.test(a.product) ? "o" : "a");
    if (part === "o") return [
      { platform: "linux", label: "Operating system release", cmd: "cat /etc/os-release; uname -r" },
      { platform: "windows", label: "Operating system build", cmd: "Get-ComputerInfo -Property OsName,OsVersion,OsBuildNumber" }];
    if (part === "h") return [
      { platform: "web-ui", label: "Device model and firmware", cmd: "Check the device's management interface or CLI ('show version' on most network devices) for model and firmware version." }];
    return [
      { platform: "linux", label: "Installed packages matching '" + t + "' (Debian/Ubuntu)", cmd: "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | grep -i '" + t + "'" },
      { platform: "linux", label: "Installed packages matching '" + t + "' (RHEL/SUSE)", cmd: "rpm -qa 2>/dev/null | grep -i '" + t + "'" },
      { platform: "windows", label: "Installed programs matching '" + t + "'", cmd: "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -match '" + t + "' | Select-Object DisplayName,DisplayVersion,Publisher" },
      { platform: "kubernetes", label: "Cluster images matching '" + t + "'", cmd: "kubectl get pods -A -o jsonpath='{..image}' | tr ' ' '\\n' | sort -u | grep -i '" + t + "'" }];
  }

  /* Build a playbook model for one CVE record. */
  function build(r, ctx) {
    var curated = (ctx.playbooks || {})[r.cve] || null;
    var lib = ctx.products || [];
    var groups = {}, order = [];
    (r.affected || []).forEach(function (a) {
      var p = matchProduct(lib, a.vendor, a.product);
      var key = p ? "lib:" + p.id : "gen:" + a.vendor + ":" + a.product;
      if (!groups[key]) { groups[key] = { product: p, vendor: a.vendor, name: p ? p.label : (a.vendor + " " + a.product).replace(/_/g, " "), ranges: [], part: a.part, sample: a }; order.push(key); }
      if (groups[key].ranges.indexOf(a.versions) < 0) groups[key].ranges.push(a.versions);
    });
    var steps = { inventory: [], configuration: [], exposure: [], detection: [], mitigation: [], verification: [] };
    if (curated) curated.steps.forEach(function (s) { steps[s.stage].push(Object.assign({ source: "curated" }, s)); });

    var others = [];
    order.forEach(function (k) {
      var g = groups[k];
      if (!g.product && curated) { others.push(g); return; }  // curated playbook: no noisy generic searches
      var checks = g.product ? g.product.checks : genericChecks(g.sample);
      checks.forEach(function (c) {
        var st = c.platform === "network" ? "exposure" : "inventory";
        steps[st].push({ stage: st, platform: c.platform, invasiveness: c.platform === "network" ? "safe-probe" : "passive",
          title: g.name + " — " + c.label, cmd: c.cmd, extract: c.extract || null, ranges: g.ranges, product: g.name,
          source: g.product ? "library" : "generic",
          positive: st === "inventory" ? "Compare the version with the affected ranges: " + g.ranges.join(" | ") + "." : "A service answers; note the version if shown.",
          negative: st === "inventory" ? "Not installed here (or under another name). Check other hosts, containers and images." : "No service on these ports from this vantage point." });
      });
      if (!g.product) steps.inventory[steps.inventory.length - 1].genericNote = true;
    });

    (r.detections || []).filter(function (d) { return d.reviewStatus !== "rejected"; }).forEach(function (d) {
      var cmd, intr = d.invasiveness === "intrusive";
      if (d.method === "nuclei") cmd = "nuclei -id " + r.cve + " -u {target}" + (intr ? "" : " -etags intrusive,dos,fuzz") + (d.outOfBand ? "" : " -ni") + " -rl 10 -jsonl -o " + r.cve + "-nuclei.jsonl";
      else if (d.method === "nmap-nse") cmd = "nmap -Pn -sV --script " + d.id + " {host}";
      else cmd = d.cmd || (d.url ? "See " + d.url : d.name || "");
      steps.detection.push({ stage: "detection", platform: d.method === "nuclei" || d.method === "nmap-nse" ? "network" : (d.platform || "network"),
        invasiveness: d.invasiveness || "safe-probe", title: ({ nuclei: "Nuclei template", "nmap-nse": "Nmap NSE script" }[d.method] || "Check") + " — " + (d.name || d.id || ""),
        cmd: cmd, url: d.url, source: d.method, reviewStatus: d.reviewStatus, outOfBand: d.outOfBand,
        positive: "Detection signal, so record as Suspected. Confirm with the version and configuration evidence (steps 1–2) before calling it Validated.",
        negative: "No result does not prove the system is safe (templates can miss backports, non-default paths and WAF-filtered paths)." });
    });

    if (!steps.verification.length) steps.verification.push({ stage: "verification", platform: "linux", invasiveness: "passive", source: "generic",
      title: "Re-run the inventory checks after patching", cmd: "# Re-run the step 1 commands on every affected host, then repeat steps 2–4.",
      positive: "A fixed version is installed and running (restart services or reboot if needed).", negative: "The old version is still reported, so the patch isn't effective yet." });

    return { cve: r.cve, record: r, curated: curated, steps: steps, others: others, groups: order.map(function (k) { return groups[k]; }) };
  }

  function fill(cmd, target) {
    var t = (target || "").trim(), host = t.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
    return cmd.replace(/\{target\}/g, t ? "'" + t + "'" : "TARGET").replace(/\{host\}/g, host || "HOST");
  }

  var DECISION = [
    ["Version outside every affected range, or the distribution advisory says the installed package is fixed", "Not affected — close (False Positive if a scanner flagged it)"],
    ["Affected version, but the vulnerable condition (step 2) is absent", "Informational — not currently exploitable; still schedule the upgrade"],
    ["Affected version and the condition present (or no condition known)", "Validated (version-based) — remediate; prioritize by exposure (step 3)"],
    ["Detection check positive but version unknown", "Suspected — confirm with steps 1–2"],
    ["Crash, compromise or exploitation indicators found", "Escalate to incident response — preserve logs and evidence"],
    ["Fixed version confirmed running after change", "Remediated — attach the verification output"],
    ["Business decides not to fix now", "Accepted Risk — record owner, compensating controls and review date"]
  ];

  /* ---------- exports ---------- */
  function md(models, opts) {
    var L = [], now = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    L.push("# Aegis ThreatWatch — validation playbook", "", "Generated " + now + (opts.tester ? " by " + opts.tester : "") + ". Run only against systems you own or are authorized to test.", "");
    models.forEach(function (m) {
      var r = m.record;
      L.push("## " + r.cve + (r.vendor ? " — " + r.vendor + " " + (r.product || "") : ""), "");
      if (m.curated) L.push("**Reviewed by " + m.curated.reviewedBy + " on " + m.curated.lastReviewed + ".** " + m.curated.summary, "");
      else L.push("_Generated from NVD data and the Aegis product library — not reviewed for this specific CVE. Read the vendor advisory for prerequisites._", "");
      if (m.curated && m.curated.conditions) { L.push("**Vulnerable when:**"); m.curated.conditions.forEach(function (c) { L.push("- " + c); }); L.push(""); }
      if (m.curated && m.curated.fixedVersions) {
        L.push("| Product | Affected | Fixed |", "|---|---|---|");
        m.curated.fixedVersions.forEach(function (f) { L.push("| " + f.product + " | " + (f.affected || "") + " | " + f.fixed + " |"); });
        L.push("");
      } else if (m.groups.length) {
        L.push("| Product | Affected versions (NVD) |", "|---|---|");
        m.groups.forEach(function (g) { L.push("| " + g.name + " | " + g.ranges.join("; ") + " |"); });
        L.push("");
      }
      if (m.others && m.others.length) L.push("Also listed by NVD (check with the vendor/distribution advisory): " + m.others.map(function (g) { return g.name + " (" + g.ranges.join("; ") + ")"; }).join(", ") + ".", "");
      STAGES.forEach(function (s) {
        var list = m.steps[s[0]];
        L.push("### " + s[1], "", "_" + s[2] + "_", "");
        if (!list.length) { L.push("No step for this stage. Check the vendor advisory.", ""); return; }
        list.forEach(function (st) {
          L.push("- [ ] **" + st.title + "** (" + (PLATFORM[st.platform] || st.platform) + ", " + st.invasiveness + ")", "",
            "```" + (st.platform === "windows" ? "powershell" : "bash"), fill(st.cmd, opts.target), "```", "",
            "  - Positive: " + st.positive, "  - Negative: " + st.negative, "  - Result: ____________________", "");
        });
      });
      if (m.curated && m.curated.mitigations) { L.push("### Mitigations"); m.curated.mitigations.forEach(function (x) { L.push("- " + x); }); L.push(""); }
      L.push("### Decision", "", "| Finding | Status |", "|---|---|");
      DECISION.forEach(function (d) { L.push("| " + d[0] + " | " + d[1] + " |"); });
      L.push("", "Final status: ____________  Confirmed by: ____________  Date: ____________", "");
      var srcs = (m.curated ? m.curated.sources : []).concat(["https://nvd.nist.gov/vuln/detail/" + r.cve]);
      L.push("Sources: " + srcs.filter(function (u, i) { return srcs.indexOf(u) === i; }).join(" · "), "");
    });
    return L.join("\n");
  }

  /* Read-only Linux check script: runs only passive Linux commands; evaluates versions. */
  function bash(models, opts) {
    var L = [], n = 0, stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    L.push("#!/usr/bin/env bash",
      "# Aegis ThreatWatch — read-only validation checks (" + models.map(function (m) { return m.cve; }).join(", ") + ")",
      "# Generated " + stamp + ". Runs ONLY local, read-only commands (version, package and config queries).",
      "# It makes no network connections and changes nothing. Run on hosts you are authorized to assess.",
      "# Some checks need sudo to read configuration. Output: aegis-validation-$(hostname)-<time>.txt",
      "set -u",
      "OUT=\"aegis-validation-$(hostname)-$(date +%Y%m%d%H%M%S).txt\"",
      "exec > >(tee \"$OUT\") 2>&1",
      "vle() { [ \"$1\" = \"$(printf '%s\\n%s\\n' \"$1\" \"$2\" | sort -V | head -n1)\" ]; }",
      "in_range() { # $1=version $2=spec e.g. '>= 1.9.5, < 1.30.7'  -> 0 match, 1 no, 2 cannot compare",
      "  local v=\"$1\" spec=\"$2\" p op val",
      "  [ \"$spec\" = \"all versions\" ] && return 0",
      "  IFS=',' read -ra P <<< \"$spec\"",
      "  for p in \"${P[@]}\"; do p=\"${p# }\"; op=\"${p%% *}\"; val=\"${p#* }\"",
      "    case \"$val\" in *[!0-9.]*) return 2;; esac",
      "    case \"$op\" in",
      "      '>=') vle \"$val\" \"$v\" || return 1;;  '>') { vle \"$val\" \"$v\" && [ \"$val\" != \"$v\" ]; } || return 1;;",
      "      '<=') vle \"$v\" \"$val\" || return 1;;  '<') { vle \"$v\" \"$val\" && [ \"$v\" != \"$val\" ]; } || return 1;;",
      "      '=') [ \"$v\" = \"$val\" ] || return 1;;  *) return 2;;",
      "    esac",
      "  done; return 0; }",
      "evaluate() { # $1=raw output $2=extract regex, rest=ranges",
      "  local raw=\"$1\" re=\"$2\"; shift 2; local v",
      "  v=$(printf '%s\\n' \"$raw\" | grep -oE \"$re\" | head -1 | grep -oE '[0-9]+(\\.[0-9]+)+' | head -1)",
      "  [ -z \"$v\" ] && { echo \"  -> version not detected; compare manually\"; return; }",
      "  local hit=0 manual=0 r; for r in \"$@\"; do in_range \"$v\" \"$r\"; case $? in 0) echo \"  -> $v IS IN AFFECTED RANGE: $r\"; hit=1;; 2) manual=1;; esac; done",
      "  [ $hit = 0 ] && echo \"  -> $v is not in the numeric affected ranges\"",
      "  [ $manual = 1 ] && echo \"  -> some ranges use non-numeric versions; compare manually\"",
      "  echo \"  NOTE: distribution packages may carry backported fixes; confirm with the distribution advisory.\"; }",
      "echo \"== Aegis ThreatWatch validation — host $(hostname) — $(date -u +%FT%TZ)\"",
      "");
    models.forEach(function (m) {
      L.push("echo; echo \"################ " + m.cve + " ################\"");
      ["inventory", "configuration", "detection", "verification"].forEach(function (stage) {
        m.steps[stage].filter(function (s) { return s.platform === "linux" && s.invasiveness === "passive" && !/\{(host|target)\}/.test(s.cmd) && s.cmd.charAt(0) !== "#"; })
          .forEach(function (s) {
            n++;
            L.push("check_" + n + "() {", s.cmd, "}");
            L.push("echo; echo \"--- [" + stage + "] " + s.title.replace(/["$`\\]/g, "") + "\"");
            L.push("out_" + n + "=$(check_" + n + " 2>&1); printf '%s\\n' \"${out_" + n + ":-  (no output)}\"");
            if (s.extract && s.ranges && s.ranges.length) {
              L.push("evaluate \"$out_" + n + "\" '" + s.extract.replace(/'/g, "") + "' " + s.ranges.map(function (x) { return "'" + x.replace(/'/g, "") + "'"; }).join(" "));
            }
          });
      });
    });
    L.push("", "echo; echo \"Saved to $OUT. Review each section against the playbook's positive/negative guidance.\"");
    return L.join("\n") + "\n";
  }

  function ps1(models) {
    var L = [], any = false;
    L.push("# Aegis ThreatWatch - read-only validation checks (" + models.map(function (m) { return m.cve; }).join(", ") + ")",
      "# Runs only local, read-only queries. Run on hosts you are authorized to assess.",
      "$Out = \"aegis-validation-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddHHmmss).txt\"",
      "Start-Transcript -Path $Out | Out-Null");
    models.forEach(function (m) {
      L.push("Write-Host \"`n################ " + m.cve + " ################\"");
      ["inventory", "configuration", "detection", "verification"].forEach(function (stage) {
        m.steps[stage].filter(function (s) { return s.platform === "windows" && s.invasiveness === "passive" && s.cmd.charAt(0) !== "#"; }).forEach(function (s) {
          any = true;
          L.push("Write-Host \"`n--- [" + stage + "] " + s.title.replace(/["`$]/g, "") + "\"", "try { " + s.cmd + " | Out-String | Write-Host } catch { Write-Host \"  (failed: $($_.Exception.Message))\" }");
        });
      });
      // Windows build evaluation: compare only against the fixed build for this host's own release line.
      var fixes = [];
      m.groups.forEach(function (g) {
        if (!g.product || g.product.id !== "windows") return;
        g.ranges.forEach(function (rg) { var mm = /^<\s*(10\.0\.\d+\.\d+)$/.exec(rg.trim()); if (mm && fixes.indexOf(mm[1]) < 0) fixes.push(mm[1]); });
      });
      if (fixes.length) {
        any = true;
        L.push("Write-Host \"`n--- [evaluate] Windows build vs fixed builds for " + m.cve + "\"",
          "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
          "$cur = [version](\"10.0.$($cv.CurrentBuild).$($cv.UBR)\")",
          "$fx = @(@(" + fixes.map(function (f) { return "'" + f + "'"; }).join(",") + ") | ForEach-Object { [version]$_ } | Where-Object { $_.Build -eq $cur.Build } | Sort-Object)",
          "if ($fx.Count -eq 0) { Write-Host \"  -> build $cur : no fixed build listed for this release line; check the Microsoft Security Update Guide\" }",
          "elseif ($cur -lt $fx[0]) { Write-Host \"  -> build $cur IS BELOW fixed build $($fx[0]) : likely VULNERABLE (confirm in the Update Guide)\" }",
          "elseif ($cur -lt $fx[-1]) { Write-Host \"  -> build $cur is between fixed builds listed for different editions ($($fx -join ', ')); check which applies to this edition\" }",
          "else { Write-Host \"  -> build $cur is at or above the fixed build: patched for this CVE\" }");
      }
    });
    L.push("Stop-Transcript | Out-Null", "Write-Host \"Saved to $Out\"");
    return any ? L.join("\r\n") + "\r\n" : null;
  }

  window.TWPlaybook = { build: build, fill: fill, md: md, bash: bash, ps1: ps1, STAGES: STAGES, PLATFORM: PLATFORM, DECISION: DECISION };
})();
