function bindEvents() {
  getEl("instServerPre").textContent = INST_SRV_UB;
  getEl("instAgentPre").textContent = INST_AG_LIN;
  renderDB();

  // Nav
  document
    .querySelectorAll(".nav-links button[data-sec]")
    .forEach(function (b) {
      b.addEventListener("click", function () {
        showSection(this.dataset.sec);
      });
    });
  // Hamburger
  getEl("navToggle").addEventListener("click", function () {
    getEl("navLinks").classList.toggle("open");
  });
  document
    .querySelectorAll(".nav-links button[data-sec]")
    .forEach(function (b) {
      b.addEventListener("click", function () {
        getEl("navLinks").classList.remove("open");
      });
    });
  getEl("navBrand").addEventListener("click", function (e) {
    e.preventDefault();
    showSection("generator");
    getEl("navLinks").classList.remove("open");
  });
  getEl("themeBtn").addEventListener("click", toggleTheme);

  // Examples
  getEl("exBtns").addEventListener("click", function (e) {
    var btn = e.target.closest("button");
    if (!btn || !exData[btn.dataset.key]) return;
    getEl("logInput").value = exData[btn.dataset.key];
    document.querySelectorAll("#mitreBadges .badge").forEach(function (b) {
      b.classList.remove("active");
    });
    selMitre = [];
  });

  // MITRE badges (auto-generated from MITRE_TECH)
  var mbHtml = "";
  var sortedTech = MITRE_TECH.slice().sort(function (a, b) {
    return a.id.localeCompare(b.id);
  });
  for (var mi = 0; mi < sortedTech.length; mi++) {
    mbHtml +=
      '<button class="badge" data-m="' +
      sortedTech[mi].id +
      '">' +
      sortedTech[mi].id +
      " " +
      sortedTech[mi].name +
      "</button>";
  }
  getEl("mitreBadges").innerHTML = mbHtml;

  getEl("mitreBadges").addEventListener("click", function (e) {
    var b = e.target.closest(".badge");
    if (!b) return;
    b.classList.toggle("active");
    var id = b.dataset.m;
    if (b.classList.contains("active")) {
      if (selMitre.indexOf(id) === -1) selMitre.push(id);
    } else {
      var idx = selMitre.indexOf(id);
      if (idx !== -1) selMitre.splice(idx, 1);
    }
  });

  // Generate / Reset
  getEl("genBtn").addEventListener("click", generateRule);
  getEl("resetBtn").addEventListener("click", resetAll);

  // Output tabs
  getEl("outTabs").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    this.querySelectorAll("button").forEach(function (t) {
      t.classList.remove("active");
    });
    b.classList.add("active");
    switchTab(b.dataset.tab);
  });
  getEl("copyBtn").addEventListener("click", copyOutput);
  getEl("validateBtn").addEventListener("click", validateXml);
  getEl("editBtn").addEventListener("click", function () {
    if (curTab === "editor") return;
    switchTab("editor");
    document.querySelectorAll("#outTabs button").forEach(function (t) {
      t.classList.remove("active");
    });
    document
      .querySelector('#outTabs button[data-tab="editor"]')
      .classList.add("active");
  });

  // Save editor changes back
  getEl("outEditor").addEventListener("input", function () {
    genData.rule = this.value;
  });

  // Save to history on generate
  var origGen = generateRule;
  generateRule = function () {
    origGen();
    var log = getEl("logInput").value.trim();
    if (!log) return;
    var det = detectType(log);
    var name = det ? det.name : "Custom Log";
    var hist = JSON.parse(localStorage.getItem("wazgenHistory") || "[]");
    hist.unshift({
      id: getEl("ruleId").value - 1,
      name: name,
      log: log.substring(0, 80),
      time: new Date().toISOString(),
      rule: genData.rule,
    });
    if (hist.length > 50) hist = hist.slice(0, 50);
    localStorage.setItem("wazgenHistory", JSON.stringify(hist));
  };

  // History
  getEl("historyClear").addEventListener("click", function () {
    if (confirm("Hapus semua riwayat?")) {
      localStorage.removeItem("wazgenHistory");
      renderHistory();
      toast("Riwayat dihapus");
    }
  });

  function renderHistory() {
    var hist = JSON.parse(localStorage.getItem("wazgenHistory") || "[]");
    var empty = getEl("historyEmpty");
    var list = getEl("historyList");
    var items = getEl("historyItems");
    var count = getEl("historyCount");
    if (hist.length === 0) {
      empty.style.display = "block";
      list.style.display = "none";
      return;
    }
    empty.style.display = "none";
    list.style.display = "block";
    count.textContent = hist.length + " item";
    items.innerHTML = hist
      .map(function (h, i) {
        var d = new Date(h.time);
        var t = d.toLocaleDateString() + " " + d.toLocaleTimeString();
        return (
          '<div class="dbi" onclick="loadHistory(' +
          i +
          ')" style="cursor:pointer">' +
          '<div class="db-item-name">[ID ' +
          h.id +
          "] " +
          h.name +
          "</div>" +
          '<div style="font-size:10px;color:var(--muted2);margin:2px 0">' +
          t +
          "</div>" +
          '<div style="font-size:10px;color:var(--muted);font-family:var(--mono)">' +
          h.log +
          "</div></div>"
        );
      })
      .join("");
  }

  window.loadHistory = function (idx) {
    var hist = JSON.parse(localStorage.getItem("wazgenHistory") || "[]");
    var h = hist[idx];
    if (!h) return;
    genData = {
      rule: h.rule,
      decoder: "",
      ossec: "",
      test: "",
      editor: h.rule,
    };
    getEl("ruleId").value = h.id;
    getEl("logInput").value = h.log;
    getEl("metaCards").innerHTML =
      '<div class="meta-card"><div class="meta-label">Rule ID</div><div class="meta-value">' +
      h.id +
      "</div></div>" +
      '<div class="meta-card"><div class="meta-label">Type</div><div class="meta-value" style="font-size:11px">' +
      h.name +
      "</div></div>" +
      '<div class="meta-card"><div class="meta-label">Source</div><div class="meta-value" style="font-size:10px">History</div></div>';
    getEl("outPanel").style.display = "block";
    switchTab("rule");
    showSection("generator");
    toast("Loaded from history");
  };

  // Override showSection to render history
  var origShow = showSection;
  showSection = function (name) {
    origShow(name);
    if (name === "history") renderHistory();
  };

  // Batch
  getEl("batchBtn").addEventListener("click", handleBatchFile);
  getEl("batchCopyAll").addEventListener("click", function () {
    var t = getEl("batchOutput").textContent;
    if (!t) return;
    if (navigator.clipboard)
      navigator.clipboard.writeText(t).then(function () {
        toast("Copied all!");
      });
  });

  // DB
  getEl("dbSearch").addEventListener("input", renderDB);
  getEl("catFilter").innerHTML = DB_CATS.map(function (c) {
    return (
      "<button" +
      (c.id === "all" ? ' class="active"' : "") +
      ' data-cat="' +
      c.id +
      '">' +
      c.name +
      "</button>"
    );
  }).join("");
  getEl("catFilter").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    this.querySelectorAll("button").forEach(function (bt) {
      bt.classList.remove("active");
    });
    b.classList.add("active");
    renderDB();
  });
  getEl("ddClose").addEventListener("click", function () {
    getEl("dbDetail").style.display = "none";
  });

  // MITRE map filter
  getEl("mitreTacticFilter").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    this.querySelectorAll("button").forEach(function (bt) {
      bt.classList.remove("active");
    });
    b.classList.add("active");
    renderMitreMap();
  });

  // Install
  getEl("instUbuntu").addEventListener("click", function () {
    getEl("instServerPre").textContent = INST_SRV_UB;
    this.className = "btn-sm btn-primary";
    getEl("instRhel").className = "btn-sm btn-secondary";
  });
  getEl("instRhel").addEventListener("click", function () {
    getEl("instServerPre").textContent = INST_SRV_RH;
    this.className = "btn-sm btn-primary";
    getEl("instUbuntu").className = "btn-sm btn-secondary";
  });
  getEl("agentLinux").addEventListener("click", function () {
    getEl("instAgentPre").textContent = INST_AG_LIN;
    this.className = "btn-sm btn-primary";
    getEl("agentWindows").className = "btn-sm btn-secondary";
    getEl("agentMacos").className = "btn-sm btn-secondary";
  });
  getEl("agentWindows").addEventListener("click", function () {
    getEl("instAgentPre").textContent = INST_AG_WIN;
    this.className = "btn-sm btn-primary";
    getEl("agentLinux").className = "btn-sm btn-secondary";
    getEl("agentMacos").className = "btn-sm btn-secondary";
  });
  getEl("agentMacos").addEventListener("click", function () {
    getEl("instAgentPre").textContent = INST_AG_MAC;
    this.className = "btn-sm btn-primary";
    getEl("agentLinux").className = "btn-sm btn-secondary";
    getEl("agentWindows").className = "btn-sm btn-secondary";
  });

  // Copy buttons
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var pre = this.parentElement.querySelector("pre");
      if (!pre) return;
      if (navigator.clipboard)
        navigator.clipboard.writeText(pre.textContent).then(function () {
          toast("Copied!");
        });
    });
  });
}
