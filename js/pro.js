/* WAZGEN Pro layer — workspace, ZIP, palette, linter, PWA, scoring */
(function () {
  "use strict";

  function el(id) {
    return document.getElementById(id);
  }
  function toast(msg) {
    if (typeof window.toast === "function") window.toast(msg);
  }
  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---------- CRC32 + ZIP (store only) ----------
  var CRC_TABLE = (function () {
    var c,
      table = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      c = n;
      for (var k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32Bytes(bytes) {
    var c = 0xffffffff;
    for (var i = 0; i < bytes.length; i++)
      c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  function strToU8(str) {
    if (typeof TextEncoder !== "undefined")
      return new TextEncoder().encode(str);
    var arr = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i) & 0xff;
    return arr;
  }

  function u16(n) {
    return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
  }
  function u32(n) {
    return new Uint8Array([
      n & 0xff,
      (n >> 8) & 0xff,
      (n >> 16) & 0xff,
      (n >> 24) & 0xff,
    ]);
  }
  function concat(parts) {
    var len = 0;
    for (var i = 0; i < parts.length; i++) len += parts[i].length;
    var out = new Uint8Array(len);
    var o = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], o);
      o += parts[j].length;
    }
    return out;
  }

  function createZip(files) {
    // files: [{name, data:string}]
    var locals = [];
    var centrals = [];
    var offset = 0;
    for (var i = 0; i < files.length; i++) {
      var name = files[i].name;
      var data = strToU8(files[i].data || "");
      var nameU8 = strToU8(name);
      var crc = crc32Bytes(data);
      var local = concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(crc),
        u32(data.length),
        u32(data.length),
        u16(nameU8.length),
        u16(0),
        nameU8,
        data,
      ]);
      var central = concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(crc),
        u32(data.length),
        u32(data.length),
        u16(nameU8.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(offset),
        nameU8,
      ]);
      locals.push(local);
      centrals.push(central);
      offset += local.length;
    }
    var centralBlob = concat(centrals);
    var end = concat([
      u32(0x06054b50),
      u16(0),
      u16(0),
      u16(files.length),
      u16(files.length),
      u32(centralBlob.length),
      u32(offset),
      u16(0),
    ]);
    return concat(locals.concat([centralBlob, end]));
  }

  function downloadBlob(filename, blob) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ---------- Workspace ----------
  var WS_KEY = "wazgenWorkspace";

  function loadWS() {
    try {
      return JSON.parse(localStorage.getItem(WS_KEY) || "[]");
    } catch (e) {
      return [];
    }
  }
  function saveWS(list) {
    localStorage.setItem(WS_KEY, JSON.stringify(list.slice(0, 200)));
    renderWorkspace();
  }

  function addCurrentToWorkspace() {
    var g = window.genData || {};
    if (!g.rule) {
      toast("Generate a rule first");
      return;
    }
    var list = loadWS();
    var id = g.rid || Date.now();
    // replace same id
    list = list.filter(function (x) {
      return String(x.rid) !== String(id);
    });
    list.unshift({
      rid: id,
      name: g.name || "Rule " + id,
      level: g.level || 7,
      rule: g.rule,
      decoder: g.decoder || "",
      ossec: g.ossec || "",
      log: (g.log || "").substring(0, 120),
      conf: g.conf || 0,
      time: new Date().toISOString(),
    });
    saveWS(list);
    toast("Added to workspace (" + list.length + ")");
  }

  function removeFromWorkspace(idx) {
    var list = loadWS();
    list.splice(idx, 1);
    saveWS(list);
  }

  function clearWorkspace() {
    if (!confirm("Clear entire workspace?")) return;
    saveWS([]);
    toast("Workspace cleared");
  }

  function exportWorkspaceZip() {
    var list = loadWS();
    if (!list.length) {
      toast("Workspace empty");
      return;
    }
    var rules = list
      .map(function (x) {
        return x.rule;
      })
      .join("\n\n");
    var decoders = list
      .map(function (x) {
        return x.decoder;
      })
      .filter(Boolean)
      .join("\n\n");
    var ossecs = [];
    var seen = {};
    list.forEach(function (x) {
      if (x.ossec && !seen[x.ossec]) {
        seen[x.ossec] = 1;
        ossecs.push(x.ossec);
      }
    });
    var readme =
      "WAZGEN Workspace Pack\n" +
      "Rules: " +
      list.length +
      "\n" +
      "Generated: " +
      new Date().toISOString() +
      "\n\n" +
      "Deploy:\n" +
      "1. Copy local_rules.xml to /var/ossec/etc/rules/\n" +
      "2. Copy local_decoder.xml to /var/ossec/etc/decoders/\n" +
      "3. Merge ossec snippets if needed\n" +
      "4. systemctl restart wazuh-manager\n" +
      "5. Test: echo 'LOG' | /var/ossec/bin/wazuh-logtest -v\n";
    var inventory = list
      .map(function (x, i) {
        return (
          i +
          1 +
          ". [" +
          x.rid +
          "] L" +
          x.level +
          " " +
          x.name +
          " conf=" +
          (x.conf || "?") +
          "%"
        );
      })
      .join("\n");
    var zip = createZip([
      { name: "local_rules.xml", data: rules },
      { name: "local_decoder.xml", data: decoders || "<!-- no custom decoders -->" },
      { name: "ossec_snippets.xml", data: ossecs.join("\n\n") || "<!-- none -->" },
      { name: "INVENTORY.txt", data: inventory },
      { name: "README.txt", data: readme },
    ]);
    downloadBlob(
      "wazgen-workspace-" + new Date().toISOString().slice(0, 10) + ".zip",
      new Blob([zip], { type: "application/zip" }),
    );
    toast("Workspace ZIP downloaded");
  }

  function exportCurrentZip() {
    var g = window.genData || {};
    if (!g.rule) {
      toast("Generate dulu");
      return;
    }
    var zip = createZip([
      { name: "local_rules.xml", data: g.rule },
      { name: "local_decoder.xml", data: g.decoder || "" },
      { name: "ossec_snippet.xml", data: g.ossec || "" },
      {
        name: "README_DEPLOY.txt",
        data:
          "WAZGEN pack\n1. local_rules.xml -> /var/ossec/etc/rules/\n2. local_decoder.xml -> /var/ossec/etc/decoders/\n3. merge ossec_snippet.xml into ossec.conf\n4. systemctl restart wazuh-manager\n",
      },
      {
        name: "sample.log",
        data: g.log || "",
      },
    ]);
    downloadBlob(
      "wazgen-rule-" + (g.rid || "pack") + ".zip",
      new Blob([zip], { type: "application/zip" }),
    );
    toast("ZIP pack downloaded");
  }

  function renderWorkspace() {
    var box = el("workspaceList");
    var count = el("workspaceCount");
    if (!box) return;
    var list = loadWS();
    if (count) count.textContent = list.length ? list.length + " rules" : "";
    if (!list.length) {
      box.innerHTML =
        '<p class="hint">Workspace empty. Generate a rule, then click “Add to workspace”.</p>';
      return;
    }
    var html =
      '<table class="history-table"><thead><tr><th>ID</th><th>Name</th><th>Lvl</th><th>Conf</th><th></th></tr></thead><tbody>';
    for (var i = 0; i < list.length; i++) {
      var x = list[i];
      html +=
        "<tr>" +
        "<td>" +
        esc(x.rid) +
        "</td>" +
        "<td>" +
        esc(x.name) +
        "</td>" +
        "<td>" +
        esc(x.level) +
        "</td>" +
        "<td>" +
        (x.conf || "—") +
        (x.conf ? "%" : "") +
        "</td>" +
        '<td style="text-align:right">' +
        '<button class="btn-xs btn-secondary" data-ws-load="' +
        i +
        '">Load</button> ' +
        '<button class="btn-xs btn-secondary" data-ws-del="' +
        i +
        '">×</button>' +
        "</td></tr>";
    }
    html += "</tbody></table>";
    box.innerHTML = html;
  }

  // ---------- Advanced linter ----------
  function lintRule(xml) {
    var issues = [];
    if (!xml || !String(xml).trim()) {
      issues.push({ sev: "error", msg: "Empty XML" });
      return issues;
    }
    try {
      var doc = new DOMParser().parseFromString(xml, "application/xml");
      if (doc.getElementsByTagName("parsererror").length) {
        issues.push({ sev: "error", msg: "Malformed XML" });
        return issues;
      }
    } catch (e) {
      issues.push({ sev: "error", msg: "XML parse failed" });
      return issues;
    }
    if (!/<rule\b/i.test(xml))
      issues.push({ sev: "error", msg: "Missing <rule>" });
    if (!/<description>/i.test(xml))
      issues.push({ sev: "warn", msg: "Missing <description>" });
    if (!/<group>/i.test(xml))
      issues.push({ sev: "warn", msg: "Missing <group>" });
    var idm = xml.match(/id="(\d+)"/);
    if (idm) {
      var id = parseInt(idm[1], 10);
      if (id < 100000)
        issues.push({
          sev: "warn",
          msg: "Rule ID " + id + " may collide with core Wazuh rules",
        });
      if (id > 120000)
        issues.push({
          sev: "info",
          msg: "Custom range tip: many teams use 100000–120000",
        });
    }
    var lvm = xml.match(/level="(\d+)"/);
    if (lvm && parseInt(lvm[1], 10) > 15)
      issues.push({ sev: "error", msg: "Level must be 0–15" });
    if (!/<match>/i.test(xml) && !/<field\b/i.test(xml) && !/<regex>/i.test(xml))
      issues.push({
        sev: "warn",
        msg: "No match/field/regex — rule may never fire",
      });
    if (/<match>[^<]{120,}/.test(xml))
      issues.push({
        sev: "warn",
        msg: "Very long <match> — prefer tighter pattern",
      });
    if (/T1078/i.test(xml) && !/<mitre>/i.test(xml))
      issues.push({ sev: "info", msg: "Consider explicit MITRE mapping" });
    if (/frequency=/.test(xml) && !/timeframe=/.test(xml))
      issues.push({
        sev: "error",
        msg: "frequency requires timeframe",
      });
    if (issues.length === 0)
      issues.push({ sev: "ok", msg: "Looks deployable" });
    return issues;
  }

  function showLint() {
    var xml =
      (window.genData && (window.curTab === "editor"
        ? el("outEditor") && el("outEditor").value
        : window.genData.rule)) ||
      (window.genData && window.genData.rule) ||
      "";
    var issues = lintRule(xml);
    var box = el("lintBox");
    if (!box) return;
    box.style.display = "block";
    box.innerHTML = issues
      .map(function (i) {
        return (
          '<div class="lint-item lint-' +
          i.sev +
          '"><span class="lint-sev">' +
          i.sev +
          "</span> " +
          esc(i.msg) +
          "</div>"
        );
      })
      .join("");
  }

  // ---------- detectType scoring wrapper ----------
  function installScoringDetect() {
    if (typeof window.detectType !== "function" || window.__scoredDetect) return;
    var orig = window.detectType;
    window.detectType = function (log) {
      // Prefer original explicit map, else score DB entries by match density
      var hit = orig(log);
      if (hit) return hit;
      if (!window.DB || !DB.length) return null;
      var best = null;
      var bestScore = 0;
      for (var i = 0; i < DB.length; i++) {
        var e = DB[i];
        var score = 0;
        if (e.rl && e.rl.mt) {
          var parts = String(e.rl.mt).split("|");
          for (var p = 0; p < parts.length; p++) {
            if (parts[p] && log.indexOf(parts[p]) !== -1) score += 3;
          }
        }
        if (e.dc && e.dc.pm && log.indexOf(e.dc.pm) !== -1) score += 2;
        if (e.prog && new RegExp("\\b" + e.prog + "\\b", "i").test(log))
          score += 2;
        if (e.ex && e.ex.length > 20) {
          // token overlap
          var tokens = e.ex.split(/\s+/).slice(0, 8);
          for (var t = 0; t < tokens.length; t++) {
            if (tokens[t].length > 4 && log.indexOf(tokens[t]) !== -1)
              score += 0.5;
          }
        }
        if (score > bestScore) {
          bestScore = score;
          best = e;
        }
      }
      if (best && bestScore >= 5) {
        var c = JSON.parse(JSON.stringify(best));
        c._score = bestScore;
        return c;
      }
      return null;
    };
    window.__scoredDetect = true;
  }

  // ---------- Command palette ----------
  var PALETTE = [
    { id: "gen", label: "Generate rule", run: function () { if (window.generateRule) window.generateRule(); } },
    { id: "copy", label: "Copy active output", run: function () { if (window.copyOutput) window.copyOutput(); } },
    { id: "pack", label: "Download ZIP pack", run: exportCurrentZip },
    { id: "ws-add", label: "Add current rule to workspace", run: addCurrentToWorkspace },
    { id: "ws-zip", label: "Export workspace ZIP", run: exportWorkspaceZip },
    { id: "lint", label: "Lint current rule", run: showLint },
    { id: "nav-gen", label: "Go to Generate", run: function () { if (window.showSection) window.showSection("generator"); } },
    { id: "nav-db", label: "Go to Patterns", run: function () { if (window.showSection) window.showSection("database"); } },
    { id: "nav-dep", label: "Go to Deploy", run: function () { if (window.showSection) window.showSection("install"); } },
    { id: "nav-ws", label: "Go to Workspace", run: function () { if (window.showSection) window.showSection("workspace"); } },
    { id: "theme", label: "Toggle theme", run: function () { if (window.toggleTheme) window.toggleTheme(); } },
    { id: "settings", label: "Open settings / AI key", run: function () { if (window.openSettings) window.openSettings(); } },
    { id: "sample-ssh", label: "Load SSH sample + generate", run: function () {
      if (window.exData && exData.ssh) el("logInput").value = exData.ssh;
      if (window.generateRule) window.generateRule();
    }},
    { id: "share", label: "Copy share link", run: function () { if (window.shareState) window.shareState(); } },
  ];

  function openPalette() {
    var m = el("paletteModal");
    if (!m) return;
    m.hidden = false;
    var input = el("paletteInput");
    var list = el("paletteList");
    input.value = "";
    renderPalette("");
    setTimeout(function () {
      input.focus();
    }, 10);
  }
  function closePalette() {
    var m = el("paletteModal");
    if (m) m.hidden = true;
  }
  function renderPalette(q) {
    var list = el("paletteList");
    if (!list) return;
    q = (q || "").toLowerCase();
    var items = PALETTE.filter(function (p) {
      return !q || p.label.toLowerCase().indexOf(q) !== -1;
    });
    list.innerHTML = items
      .map(function (p, i) {
        return (
          '<button type="button" class="palette-item' +
          (i === 0 ? " active" : "") +
          '" data-pal="' +
          p.id +
          '">' +
          esc(p.label) +
          "</button>"
        );
      })
      .join("");
  }
  function runPalette(id) {
    for (var i = 0; i < PALETTE.length; i++) {
      if (PALETTE[i].id === id) {
        closePalette();
        PALETTE[i].run();
        return;
      }
    }
  }

  // ---------- Extra patterns (high value) ----------
  function injectExtraPatterns() {
    if (!window.DB) return;
    var extra = [
      {
        id: "okta_mfa_fail",
        cat: "cloud",
        name: "Okta MFA Failure",
        prog: "okta",
        fmt: "json",
        ex: '{"eventType":"user.authentication.auth_via_mfa","outcome":{"result":"FAILURE"},"actor":{"alternateId":"user@corp.com"},"client":{"ipAddress":"203.0.113.10"}}',
        dc: { n: "okta-json", p: "json", ty: "json", pm: "auth_via_mfa" },
        rl: {
          lv: 10,
          gr: "authentication_failed,okta,cloud",
          mt: "auth_via_mfa",
          ds: "Okta MFA authentication failure",
        },
        mi: ["T1110", "T1078"],
        th: "Monitor",
      },
      {
        id: "aws_console_login_fail",
        cat: "cloud",
        name: "AWS Console Login Fail",
        prog: "cloudtrail",
        fmt: "json",
        ex: '{"eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Failure"},"sourceIPAddress":"198.51.100.22","userIdentity":{"userName":"admin"}}',
        dc: { n: "cloudtrail-json", p: "json", ty: "json", pm: "ConsoleLogin" },
        rl: {
          lv: 10,
          gr: "authentication_failed,aws,cloud",
          mt: "ConsoleLogin",
          ds: "AWS console login failure",
        },
        mi: ["T1110", "T1078"],
        th: "Monitor",
      },
      {
        id: "k8s_secret_get",
        cat: "container",
        name: "K8s Secret Access",
        prog: "kube-apiserver",
        fmt: "json",
        ex: '{"verb":"get","objectRef":{"resource":"secrets","name":"db-pass"},"user":{"username":"system:serviceaccount:default:evil"},"sourceIPs":["10.0.0.5"]}',
        dc: { n: "k8s-audit", p: "json", ty: "json", pm: "secrets" },
        rl: {
          lv: 12,
          gr: "kubernetes,secrets,pci_dss",
          mt: "secrets",
          ds: "Kubernetes secret access",
        },
        mi: ["T1552", "T1613"],
        th: "Investigate",
      },
      {
        id: "nginx_4xx_burst",
        cat: "web",
        name: "Nginx Client Error Burst",
        prog: "nginx",
        fmt: "syslog",
        ex: '10.0.0.8 - - [29/Jun/2026:10:23:11 +0000] "GET /wp-login.php HTTP/1.1" 404 123 "-" "scanner"',
        dc: {
          n: "nginx-access",
          p: "nginx",
          pm: "GET|POST",
          rx: '(\\d+\\.\\d+\\.\\d+\\.\\d+) .+ "(\\w+) (\\S+) HTTP/[\\d\\.]+" (\\d+)',
          o: "srcip, method, url, status",
        },
        rl: {
          lv: 7,
          gr: "web,recon",
          mt: "wp-login.php",
          ds: "WordPress login path probed",
        },
        mi: ["T1190", "T1595"],
        th: "Monitor",
      },
      {
        id: "powershell_enc",
        cat: "win",
        name: "PowerShell Encoded Command",
        prog: "powershell",
        fmt: "win",
        ex: "EventID=4104 ScriptBlockText=powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0",
        dc: {
          n: "win-ps",
          p: "windows-event",
          pm: "EventID=4104",
          rx: "EventID=(\\d+).*ScriptBlockText=(.+)",
          o: "id, script",
        },
        rl: {
          lv: 12,
          gr: "windows,powershell,attack",
          mt: "-enc",
          ds: "Encoded PowerShell command",
        },
        mi: ["T1059.001", "T1027"],
        th: "Investigate",
      },
      {
        id: "sshd_maxstartups",
        cat: "auth",
        name: "SSH MaxStartups",
        prog: "sshd",
        fmt: "syslog",
        ex: "Jun 29 10:23:11 server sshd[99]: error: beginning MaxStartups throttling",
        dc: {
          n: "sshd-maxstartups",
          p: "sshd",
          pm: "MaxStartups",
          rx: "MaxStartups throttling",
          o: "message",
        },
        rl: {
          lv: 10,
          gr: "authentication_failed,sshd,dos",
          mt: "MaxStartups",
          ds: "SSH connection throttling (possible brute force)",
        },
        mi: ["T1110"],
        th: "Investigate",
      },
      {
        id: "clamav_found",
        cat: "malware",
        name: "ClamAV Detection",
        prog: "clamd",
        fmt: "syslog",
        ex: "Jun 29 10:23:11 server clamd[10]: /var/www/html/shell.php: PHP.Shell.Agent FOUND",
        dc: {
          n: "clamav",
          p: "clamd",
          pm: "FOUND",
          rx: "(.+): (.+) FOUND",
          o: "file, signature",
        },
        rl: {
          lv: 12,
          gr: "malware,clamav",
          mt: "FOUND",
          ds: "ClamAV malware detection",
        },
        mi: ["T1505.003", "T1204"],
        th: "Contain",
      },
      {
        id: "github_pat_leak",
        cat: "other",
        name: "GitHub PAT Pattern",
        prog: "custom",
        fmt: "syslog",
        ex: "app ERROR token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 leaked in logs",
        dc: {
          n: "secret-leak",
          p: "",
          pm: "ghp_",
          rx: "(ghp_[A-Za-z0-9]{20,})",
          o: "token",
        },
        rl: {
          lv: 14,
          gr: "secrets,pci_dss,gdpr",
          mt: "ghp_",
          ds: "Possible GitHub personal access token in logs",
        },
        mi: ["T1552"],
        th: "Rotate secret",
      },
    ];
    var have = {};
    for (var i = 0; i < DB.length; i++) have[DB[i].id] = 1;
    for (var j = 0; j < extra.length; j++) {
      if (!have[extra[j].id]) DB.push(extra[j]);
    }
  }

  // ---------- PWA ----------
  function registerPWA() {
    if (!("serviceWorker" in navigator)) return;
    navigator.serviceWorker.register("./sw.js").catch(function () {});
  }

  // ---------- Wire UI ----------
  function bindPro() {
    installScoringDetect();
    injectExtraPatterns();
    registerPWA();
    renderWorkspace();

    // Override download pack to ZIP if present
    if (typeof window.downloadPack === "function") {
      window.downloadPack = exportCurrentZip;
    }
    window.exportCurrentZip = exportCurrentZip;
    window.addCurrentToWorkspace = addCurrentToWorkspace;
    window.exportWorkspaceZip = exportWorkspaceZip;
    window.lintRule = lintRule;
    window.renderWorkspace = renderWorkspace;
    window.openPalette = openPalette;

    var addBtn = el("wsAddBtn");
    if (addBtn) addBtn.addEventListener("click", addCurrentToWorkspace);
    var zipBtn = el("wsZipBtn");
    if (zipBtn) zipBtn.addEventListener("click", exportWorkspaceZip);
    var clearBtn = el("wsClearBtn");
    if (clearBtn) clearBtn.addEventListener("click", clearWorkspace);
    var lintBtn = el("lintBtn");
    if (lintBtn) lintBtn.addEventListener("click", showLint);

    var wsBox = el("workspaceList");
    if (wsBox) {
      wsBox.addEventListener("click", function (e) {
        var t = e.target.closest("[data-ws-del],[data-ws-load]");
        if (!t) return;
        if (t.hasAttribute("data-ws-del")) {
          removeFromWorkspace(parseInt(t.getAttribute("data-ws-del"), 10));
        } else if (t.hasAttribute("data-ws-load")) {
          var list = loadWS();
          var item = list[parseInt(t.getAttribute("data-ws-load"), 10)];
          if (!item) return;
          window.genData = {
            rule: item.rule,
            decoder: item.decoder,
            ossec: item.ossec,
            test: "",
            editor: item.rule,
            rid: item.rid,
            level: item.level,
            name: item.name,
            conf: item.conf,
            log: item.log,
          };
          if (el("ruleId")) el("ruleId").value = item.rid;
          if (el("logInput")) el("logInput").value = item.log || "";
          if (window.setOutputVisible) window.setOutputVisible(true);
          if (window.switchTab) window.switchTab("rule");
          if (window.showSection) window.showSection("generator");
          toast("Loaded from workspace");
        }
      });
    }

    // hook nav for workspace
    document.querySelectorAll(".nav-links button[data-sec]").forEach(function (b) {
      b.addEventListener("click", function () {
        if (this.dataset.sec === "workspace") renderWorkspace();
      });
    });

    // palette
    var pInput = el("paletteInput");
    if (pInput) {
      pInput.addEventListener("input", function () {
        renderPalette(this.value);
      });
      pInput.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
          closePalette();
          return;
        }
        if (e.key === "Enter") {
          var act = el("paletteList") && el("paletteList").querySelector(".palette-item.active");
          if (act) runPalette(act.getAttribute("data-pal"));
        }
      });
    }
    var pList = el("paletteList");
    if (pList) {
      pList.addEventListener("click", function (e) {
        var b = e.target.closest("[data-pal]");
        if (b) runPalette(b.getAttribute("data-pal"));
      });
    }
    document.querySelectorAll("[data-close-palette]").forEach(function (n) {
      n.addEventListener("click", closePalette);
    });

    document.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openPalette();
      }
      if (e.key === "Escape") closePalette();
    });

    // auto-lint after generate: patch generateRule toast side via MutationObserver on outPanel
    var out = el("outPanel");
    if (out) {
      var obs = new MutationObserver(function () {
        if (out.style.display !== "none" && window.genData && window.genData.rule) {
          showLint();
        }
      });
      obs.observe(out, { attributes: true, attributeFilter: ["style"] });
    }

    // Improve history save to include decoder/ossec if generateRule override exists — soft patch
    // on download pack button if id exists (already may be rebound)
    /* download handled below */


    var paletteBtn = el("paletteBtn");
    if (paletteBtn) paletteBtn.addEventListener("click", openPalette);
    var wsAddFromGen = el("wsAddFromGen");
    if (wsAddFromGen) wsAddFromGen.addEventListener("click", addCurrentToWorkspace);

    // Replace download pack button listeners cleanly
    var dl = el("downloadPackBtn");
    if (dl) {
      var ndl = dl.cloneNode(true);
      dl.parentNode.replaceChild(ndl, dl);
      ndl.addEventListener("click", function (e) {
        e.preventDefault();
        exportCurrentZip();
      });
    }

  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      setTimeout(bindPro, 50);
    });
  } else {
    setTimeout(bindPro, 50);
  }
})();
