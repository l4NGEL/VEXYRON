(function () {
  "use strict";

  function $(sel, root) {
    return (root || document).querySelector(sel);
  }
  function $$(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  function initSidebar() {
    var btn = $("#menu-btn");
    var toggle = $("#sidebar-toggle");
    var sidebar = $("#sidebar");
    var backdrop = $("#sidebar-backdrop");
    if (!sidebar) return;

    try {
      if (localStorage.getItem("pl-sidebar") === "collapsed") sidebar.classList.add("collapsed");
    } catch (e) {}

    function closeMobile() {
      sidebar.classList.remove("open");
      if (backdrop) backdrop.hidden = true;
      document.body.classList.remove("nav-open");
    }
    function openMobile() {
      sidebar.classList.add("open");
      if (backdrop) backdrop.hidden = false;
      document.body.classList.add("nav-open");
    }

    if (btn) {
      btn.addEventListener("click", function () {
        if (sidebar.classList.contains("open")) closeMobile();
        else openMobile();
      });
    }
    if (toggle) {
      toggle.addEventListener("click", function () {
        if (window.matchMedia("(max-width: 860px)").matches) {
          if (sidebar.classList.contains("open")) closeMobile();
          else openMobile();
          return;
        }
        sidebar.classList.toggle("collapsed");
        try {
          localStorage.setItem("pl-sidebar", sidebar.classList.contains("collapsed") ? "collapsed" : "open");
        } catch (e) {}
      });
    }
    if (backdrop) backdrop.addEventListener("click", closeMobile);
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeMobile();
    });
  }

  function isPrivateTarget(raw) {
    var value = (raw || "").trim();
    if (!value) return true;
    try {
      if (!/^https?:\/\//i.test(value)) value = "http://" + value;
      var host = new URL(value).hostname.toLowerCase();
      if (host === "localhost" || host === "::1" || host.endsWith(".local")) return true;
      if (host === "127.0.0.1" || host.indexOf("127.") === 0) return true;
      var m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
      if (!m) return false;
      var a = +m[1], b = +m[2];
      if (a === 10) return true;
      if (a === 192 && b === 168) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      return false;
    } catch (e) {
      return true;
    }
  }

  function initScanForm() {
    var form = $("#scan-form");
    if (!form) return;

    var urlInput = form.querySelector('input[name="url"]');
    var authBox = $("#auth-warning");
    var authCheck = form.querySelector('input[name="i_authorize"]');
    var overlay = $("#scan-overlay");
    var btn = $("#scan-btn");
    var advanced = form.querySelector("details.advanced");

    function syncAuthWarning() {
      if (!authBox || !urlInput) return;
      var priv = isPrivateTarget(urlInput.value);
      authBox.hidden = priv;
      if (!priv && advanced) advanced.open = true;
    }

    if (urlInput) {
      urlInput.addEventListener("input", syncAuthWarning);
      urlInput.addEventListener("blur", syncAuthWarning);
      syncAuthWarning();
    }

    $$(".toggle-secret").forEach(function (toggle) {
      toggle.addEventListener("click", function () {
        var input = document.getElementById(toggle.getAttribute("data-for"));
        if (!input) return;
        var show = input.type === "password";
        input.type = show ? "text" : "password";
        toggle.setAttribute("aria-label", show ? "Şifreyi gizle" : "Şifreyi göster");
        toggle.classList.toggle("is-shown", show);
      });
    });

    var apkFile = $("#apk_file");
    var apkFolder = $("#apk_folder");
    var apkPicked = $("#apk-picked");
    var apkDrop = $("#apk-drop");
    var acceptedFile = $("#accepted_file");
    var acceptedPicked = $("#accepted-picked");
    var pendingFolder = [];

    function assignFiles(input, files) {
      if (!input || typeof DataTransfer === "undefined") return false;
      var dt = new DataTransfer();
      files.forEach(function (f) { dt.items.add(f); });
      input.files = dt.files;
      return true;
    }

    function markDrop(zone, picked, text) {
      if (!zone) return;
      var has = !!text;
      zone.classList.toggle("has-file", has);
      if (picked) {
        picked.hidden = !has;
        picked.textContent = text || "";
      }
    }

    function clearApkUploads() {
      pendingFolder = [];
      if (apkFile) apkFile.value = "";
      if (apkFolder) apkFolder.value = "";
      markDrop(apkDrop, apkPicked, "");
    }

    function setApkLabel() {
      if (pendingFolder.length) {
        markDrop(apkDrop, apkPicked, pendingFolder.length + " dosya (klasör)");
        return;
      }
      if (apkFolder && apkFolder.files && apkFolder.files.length) {
        markDrop(apkDrop, apkPicked, apkFolder.files.length + " dosya (klasör)");
        return;
      }
      if (apkFile && apkFile.files && apkFile.files[0]) {
        markDrop(apkDrop, apkPicked, apkFile.files[0].name);
        return;
      }
      markDrop(apkDrop, apkPicked, "");
    }

    function collectDirectory(entry, prefix) {
      return new Promise(function (resolve) {
        var acc = [];
        function walk(ent, pre) {
          return new Promise(function (res) {
            if (!ent) return res();
            if (ent.isFile) {
              ent.file(function (file) {
                acc.push({ file: file, rel: pre + file.name });
                res();
              }, function () { res(); });
              return;
            }
            if (!ent.isDirectory) return res();
            var reader = ent.createReader();
            var all = [];
            function readBatch() {
              reader.readEntries(function (entries) {
                if (!entries.length) {
                  Promise.all(all).then(function () { res(); });
                  return;
                }
                entries.forEach(function (child) {
                  all.push(walk(child, pre + ent.name + "/"));
                });
                readBatch();
              }, function () { res(); });
            }
            readBatch();
          });
        }
        walk(entry, prefix).then(function () { resolve(acc); });
      });
    }

    function bindDropZone(zone, onFiles) {
      if (!zone) return;
      ["dragenter", "dragover"].forEach(function (evt) {
        zone.addEventListener(evt, function (e) {
          e.preventDefault();
          e.stopPropagation();
          zone.classList.add("is-drag");
        });
      });
      ["dragleave", "drop"].forEach(function (evt) {
        zone.addEventListener(evt, function (e) {
          e.preventDefault();
          e.stopPropagation();
          if (evt === "dragleave") zone.classList.remove("is-drag");
        });
      });
      zone.addEventListener("drop", function (e) {
        zone.classList.remove("is-drag");
        onFiles(e.dataTransfer);
      });
    }

    if (apkDrop && apkFile) {
      apkDrop.addEventListener("click", function (e) {
        if (e.target.closest(".drop-folder-btn")) return;
        apkFile.click();
      });
      apkDrop.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          apkFile.click();
        }
      });
      apkFile.addEventListener("change", function () {
        pendingFolder = [];
        if (apkFolder) apkFolder.value = "";
        setApkLabel();
        syncCoverage();
      });
      bindDropZone(apkDrop, function (dt) {
        var item = dt && dt.items && dt.items[0];
        var entry = item && item.webkitGetAsEntry && item.webkitGetAsEntry();
        if (entry && entry.isDirectory) {
          collectDirectory(entry, "").then(function (acc) {
            pendingFolder = acc.slice(0, 4000);
            if (apkFile) apkFile.value = "";
            if (apkFolder) apkFolder.value = "";
            setApkLabel();
            syncCoverage();
          });
          return;
        }
        var file = dt && dt.files && dt.files[0];
        if (!file) return;
        var name = (file.name || "").toLowerCase();
        if (!name.endsWith(".apk") && !name.endsWith(".zip")) return;
        pendingFolder = [];
        if (apkFolder) apkFolder.value = "";
        assignFiles(apkFile, [file]);
        setApkLabel();
        syncCoverage();
      });
    }

    var folderBtn = $("#apk-folder-btn");
    if (folderBtn && apkFolder) {
      folderBtn.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        apkFolder.click();
      });
      apkFolder.addEventListener("change", function () {
        pendingFolder = [];
        if (apkFile) apkFile.value = "";
        setApkLabel();
        syncCoverage();
      });
    }

    var acceptedDrop = $("#accepted-drop");
    if (acceptedDrop && acceptedFile) {
      acceptedDrop.addEventListener("click", function () { acceptedFile.click(); });
      acceptedDrop.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          acceptedFile.click();
        }
      });
      acceptedFile.addEventListener("change", function () {
        var f = acceptedFile.files && acceptedFile.files[0];
        markDrop(acceptedDrop, acceptedPicked, f ? f.name : "");
      });
      bindDropZone(acceptedDrop, function (dt) {
        var file = dt && dt.files && dt.files[0];
        if (!file || !(file.name || "").toLowerCase().endsWith(".json")) return;
        assignFiles(acceptedFile, [file]);
        markDrop(acceptedDrop, acceptedPicked, file.name);
      });
    }

    function applyProfile(name) {
      $$(".profile[data-profile]").forEach(function (p) {
        p.classList.toggle("active", p.getAttribute("data-profile") === name);
      });
      var net = form.querySelector('input[name="scan_network"]');
      var db = form.querySelector('input[name="scan_database"]');
      var noApi = form.querySelector('input[name="no_api"]');
      var load = form.querySelector('input[name="load_test"]');
      var scanApk = form.querySelector('input[name="scan_apk"]');
      if (name === "quick") {
        if (advanced) advanced.open = false;
        if (net) net.checked = false;
        if (db) db.checked = false;
        if (load) load.checked = false;
        if (noApi) noApi.checked = false;
        if (scanApk) scanApk.checked = false;
      } else if (name === "auth") {
        if (advanced) advanced.open = true;
        if (net) net.checked = false;
        if (db) db.checked = false;
        if (load) load.checked = false;
        if (scanApk) scanApk.checked = false;
        var user = form.querySelector('input[name="username"]');
        if (user) user.focus();
      } else if (name === "full") {
        if (advanced) advanced.open = true;
        if (net) net.checked = true;
        if (db) db.checked = true;
        if (load) load.checked = false;
        if (noApi) noApi.checked = false;
        var host = form.querySelector('input[name="host"]');
        var scanApk = form.querySelector('input[name="scan_apk"]');
        if (host && !host.value) host.value = "127.0.0.1";
        if (scanApk) scanApk.checked = false;
      }
      syncCoverage();
    }

    $$(".profile[data-profile]").forEach(function (p) {
      p.addEventListener("click", function () {
        applyProfile(p.getAttribute("data-profile"));
      });
    });

    var fillDemo = $("#fill-demo");
    if (fillDemo) {
      fillDemo.addEventListener("click", function () {
        var map = {
          url: "http://127.0.0.1:5000",
          login_path: "/login",
          username: "admin",
          password: "admin123",
          second_username: "ayse",
          second_password: "ayse2024",
          host: "127.0.0.1",
        };
        Object.keys(map).forEach(function (name) {
          var el = form.querySelector('[name="' + name + '"]');
          if (el) el.value = map[name];
        });
        if (advanced) advanced.open = true;
        applyProfile("full");
        syncAuthWarning();
        toast("Lab demosu dolduruldu", "ok");
      });
    }

    function syncCoverage() {
      var chips = $$("[data-cov]");
      if (!chips.length) return;
      var user = (form.querySelector('input[name="username"]') || {}).value;
      var pass = (form.querySelector('input[name="password"]') || {}).value;
      var second = (form.querySelector('input[name="second_username"]') || {}).value;
      var net = form.querySelector('input[name="scan_network"]');
      var db = form.querySelector('input[name="scan_database"]');
      var noApi = form.querySelector('input[name="no_api"]');
      var apkPath = (form.querySelector('input[name="apk_path"]') || {}).value;
      var scanApk = form.querySelector('input[name="scan_apk"]');
      var hasApkUpload = (apkFile && apkFile.files && apkFile.files.length) ||
        (apkFolder && apkFolder.files && apkFolder.files.length) ||
        pendingFolder.length;
      var load = form.querySelector('input[name="load_test"]');
      var smoke = form.querySelector('input[name="smoke_test"]');
      var state = {
        auth: !!(user && pass),
        bac: !!second,
        api: !(noApi && noApi.checked),
        network: !!(net && net.checked),
        database: !!(db && db.checked),
        apk: !!(hasApkUpload || (scanApk && scanApk.checked && apkPath)),
        load: !!(load && load.checked),
        smoke: !!(smoke && smoke.checked),
      };
      chips.forEach(function (chip) {
        var key = chip.getAttribute("data-cov");
        chip.classList.toggle("on", !!state[key]);
      });
    }

    ["input", "change"].forEach(function (evt) {
      form.addEventListener(evt, syncCoverage);
    });
    syncCoverage();

    form.addEventListener("submit", function () {
      var relBox = $("#apk-rel-fields");
      if (relBox) relBox.innerHTML = "";
      var rels = [];
      if (pendingFolder.length) {
        assignFiles(apkFolder, pendingFolder.map(function (item) { return item.file; }));
        rels = pendingFolder.map(function (item) { return item.rel; });
      } else if (apkFolder && apkFolder.files && apkFolder.files.length) {
        Array.prototype.forEach.call(apkFolder.files, function (f) {
          rels.push(f.webkitRelativePath || f.name);
        });
      }
      rels.forEach(function (rel) {
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "apk_folder_rel";
        hidden.value = rel;
        (relBox || form).appendChild(hidden);
      });
      if (btn) {
        btn.disabled = true;
        btn.classList.add("is-busy");
        var label = btn.querySelector(".btn-label");
        if (label) label.textContent = "Taranıyor…";
      }
      if (overlay) overlay.hidden = false;
    });

    if (authCheck) {
      authCheck.addEventListener("change", function () {
        var card = authCheck.closest(".check-emphasis");
        if (card) card.classList.toggle("on", authCheck.checked);
      });
    }

    var reset = $("#reset-form");
    if (reset) {
      reset.addEventListener("click", function () {
        form.reset();
        if (urlInput) urlInput.value = "http://127.0.0.1:5000";
        if (typeof clearApkUploads === "function") clearApkUploads();
        if (acceptedFile) acceptedFile.value = "";
        markDrop($("#accepted-drop"), acceptedPicked, "");
        applyProfile("quick");
        syncAuthWarning();
        toast("Form varsayılanlara alındı", "ok");
      });
    }
  }

  function initResults() {
    var root = $("#findings-root");
    if (!root) return;
    var search = $("#finding-search");
    var chips = $$("[data-filter]");
    var cards = $$(".finding[data-severity]");
    var empty = $("#filter-empty");
    var current = "all";

    function apply() {
      var q = (search && search.value || "").trim().toLowerCase();
      var shown = 0;
      cards.forEach(function (card) {
        var sev = card.getAttribute("data-severity");
        var cat = (card.getAttribute("data-category") || "").toLowerCase();
        var text = (card.getAttribute("data-text") || "").toLowerCase();
        var okSev = current === "all" || current === sev || current === cat;
        var okQ = !q || text.indexOf(q) !== -1;
        var show = okSev && okQ;
        card.hidden = !show;
        if (show) shown += 1;
      });
      if (empty) empty.hidden = shown !== 0;
    }

    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        current = chip.getAttribute("data-filter");
        chips.forEach(function (c) { c.classList.toggle("active", c === chip); });
        apply();
      });
    });
    if (search) search.addEventListener("input", apply);

    $$(".copy-id").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-id") || "";
        if (!id || !navigator.clipboard) return;
        navigator.clipboard.writeText(id).then(function () {
          btn.classList.add("copied");
          btn.textContent = "kopyalandı";
          setTimeout(function () {
            btn.classList.remove("copied");
            btn.textContent = "#" + id;
          }, 1200);
        });
      });
    });
  }

  function initSearchList(inputSel, itemSel) {
    var input = $(inputSel);
    if (!input) return;
    var items = $$(itemSel);
    var empty = $("#list-empty");
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var shown = 0;
      items.forEach(function (item) {
        var text = (item.getAttribute("data-text") || item.textContent || "").toLowerCase();
        var show = !q || text.indexOf(q) !== -1;
        item.hidden = !show;
        if (show) shown += 1;
      });
      if (empty) empty.hidden = shown !== 0;
    });
  }

  function initVulnDb() {
    var input = $("#vulndb-search");
    if (!input) return;
    var items = $$(".vulndb-item");
    var cats = $$(".vulndb-category");
    var empty = $("#list-empty");
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var shown = 0;
      items.forEach(function (item) {
        var text = (item.getAttribute("data-text") || "").toLowerCase();
        var show = !q || text.indexOf(q) !== -1;
        item.hidden = !show;
        if (show) shown += 1;
      });
      cats.forEach(function (cat) {
        var el = cat.nextElementSibling;
        var any = false;
        while (el && !el.classList.contains("vulndb-category")) {
          if (el.classList.contains("vulndb-item") && !el.hidden) any = true;
          el = el.nextElementSibling;
        }
        cat.hidden = !any;
      });
      if (empty) empty.hidden = shown !== 0;
    });
  }

  function initCopyButtons() {
    $$(".copy-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy") || "";
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          var prev = btn.textContent;
          btn.textContent = "kopyalandı";
          setTimeout(function () { btn.textContent = prev; }, 1200);
        });
      });
    });
  }

  function toast(message, kind) {
    var wrap = $("#toast-wrap");
    if (!wrap || !message) return;
    var el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.textContent = message;
    wrap.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 2800);
  }

  function initTheme() {
    var btn = $("#theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var dark = document.documentElement.getAttribute("data-theme") === "dark";
      if (dark) document.documentElement.removeAttribute("data-theme");
      else document.documentElement.setAttribute("data-theme", "dark");
      try {
        localStorage.setItem("pl-theme", dark ? "light" : "dark");
      } catch (e) {}
    });
  }

  function initPopovers() {
    var userBtn = $("#user-card-btn");
    var userMenu = $("#user-menu");
    var notifBtn = $("#notif-btn");
    var notifMenu = $("#notif-menu");

    function closeAll() {
      if (userMenu) userMenu.hidden = true;
      if (notifMenu) notifMenu.hidden = true;
      if (userBtn) userBtn.setAttribute("aria-expanded", "false");
      if (notifBtn) notifBtn.setAttribute("aria-expanded", "false");
    }

    if (userBtn && userMenu) {
      userBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        var open = userMenu.hidden;
        closeAll();
        userMenu.hidden = !open;
        userBtn.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }
    if (notifBtn && notifMenu) {
      notifBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        var open = notifMenu.hidden;
        closeAll();
        notifMenu.hidden = !open;
        notifBtn.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }
    document.addEventListener("click", closeAll);
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeAll();
    });
  }

  initSidebar();
  initTheme();
  initPopovers();
  initScanForm();
  initResults();
  initSearchList("#history-search", ".history-row");
  initVulnDb();
  initCopyButtons();
})();
