(function () {
  "use strict";

  var table = document.getElementById("loot-table");
  if (!table) { return; }

  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute("content") : "";
  var status = document.getElementById("loot-status");
  var count = document.getElementById("loot-count");
  var search = document.getElementById("f-loot");
  var verdict = document.getElementById("f-verdict");
  var rows = Array.prototype.slice.call(table.tBodies[0].rows);

  function say(text) { if (status) { status.textContent = text; } }

  // Filtering and selection are deliberately coupled: "select all shown" has to
  // mean what it says, so a row hidden by the filter is also unticked. Leaving
  // a hidden row ticked is how someone downloads a sample they cannot see.
  function visible() {
    return rows.filter(function (row) { return row.style.display !== "none"; });
  }

  function apply() {
    var term = (search.value || "").trim().toLowerCase();
    var want = verdict.value;
    var shown = 0;

    rows.forEach(function (row) {
      var hit = (!term || row.getAttribute("data-search").indexOf(term) !== -1)
             && (!want || row.getAttribute("data-verdict") === want);
      row.style.display = hit ? "" : "none";
      if (hit) { shown += 1; }
      else {
        var tick = row.querySelector(".loot-tick");
        if (tick) { tick.checked = false; }
      }
    });

    if (count) {
      count.textContent = shown === rows.length
        ? rows.length + " sample" + (rows.length === 1 ? "" : "s")
        : shown + " of " + rows.length + " shown";
    }
    refresh();
  }

  function selected() {
    return visible()
      .map(function (row) { return row.querySelector(".loot-tick"); })
      .filter(function (tick) { return tick && tick.checked && !tick.disabled; })
      .map(function (tick) { return tick.value; });
  }

  function refresh() {
    var n = selected().length;
    var head = document.getElementById("loot-head-tick");
    if (head) {
      var pool = visible().filter(function (row) {
        var tick = row.querySelector(".loot-tick");
        return tick && !tick.disabled;
      });
      head.checked = pool.length > 0 && n === pool.length;
      head.indeterminate = n > 0 && n < pool.length;
    }
    say(n ? n + " selected" : "");
  }

  function setAll(state) {
    visible().forEach(function (row) {
      var tick = row.querySelector(".loot-tick");
      if (tick && !tick.disabled) { tick.checked = state; }
    });
    refresh();
  }

  search.addEventListener("input", apply);
  verdict.addEventListener("change", apply);
  table.addEventListener("change", function (event) {
    if (event.target.classList.contains("loot-tick")) { refresh(); }
  });

  document.getElementById("loot-all").addEventListener("click", function () { setAll(true); });
  document.getElementById("loot-none").addEventListener("click", function () { setAll(false); });
  var head = document.getElementById("loot-head-tick");
  if (head) {
    head.addEventListener("change", function () { setAll(head.checked); });
  }

  // Copy buttons. navigator.clipboard needs a secure context, and the dashboard
  // is reached as plain http over an SSH tunnel, so it is usually absent --
  // hence the textarea fallback rather than a clipboard API call that silently
  // rejects on exactly the deployment the README tells you to build.
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button) { return; }
    var text = button.getAttribute("data-copy");
    var done = function () {
      var was = button.textContent;
      button.textContent = "copied";
      setTimeout(function () { button.textContent = was; }, 1200);
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
    } else {
      fallback(text, done);
    }
  });

  function fallback(text, done) {
    var scratch = document.createElement("textarea");
    scratch.value = text;
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);
    scratch.select();
    try { document.execCommand("copy"); done(); } catch (error) { say("Copy failed."); }
    document.body.removeChild(scratch);
  }

  document.getElementById("loot-rescan").addEventListener("click", function () {
    var digests = selected();
    if (!digests.length) { say("Nothing selected."); return; }

    say("Queueing…");
    fetch("/api/loot/rescan", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ digests: digests })
    })
      .then(function (response) { return response.json(); })
      .then(function (body) {
        if (!body.ok) { say("Failed: " + (body.error || "unknown")); return; }
        // The delay is the honest number, not a spinner: intel collects markers
        // on its own poll, so the verdict will not have changed by the time the
        // page reloads and saying otherwise would just look broken.
        say(body.queued + " queued — intel collects them within "
            + body.poll_seconds + "s, then VirusTotal is asked again.");
      })
      .catch(function () { say("Request failed."); });
  });

  document.getElementById("loot-download").addEventListener("click", function () {
    var digests = selected();
    if (!digests.length) { say("Nothing selected."); return; }
    if (!window.confirm(
          "Download " + digests.length + " live malware sample(s)?\n\n"
        + "The archive is encrypted so your antivirus will not inspect it, "
        + "which means it will not warn you either. Open only in a disposable VM.")) {
      return;
    }

    say("Building archive…");
    fetch("/api/loot/download", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ digests: digests })
    })
      .then(function (response) {
        // A failure comes back as JSON, a success as a zip. Reading the wrong
        // one gives either a blob full of an error message or an exception, so
        // branch on the status before touching the body.
        if (!response.ok) {
          return response.json().then(function (body) {
            throw new Error(body.error || "download refused");
          });
        }
        return response.blob();
      })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = "drosera-loot.zip";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        say(digests.length + " sample(s) downloaded — encrypted, password on the banner above.");
      })
      .catch(function (error) { say("Failed: " + error.message); });
  });

  // ------------------------------------------------------------- the viewer
  //
  // Every write into the panel below uses textContent. Never innerHTML, and
  // never insertAdjacentHTML: the string being rendered is a live payload, and
  // the one thing that must not happen is the browser deciding some of it is
  // markup. The server has already rewritten control characters (safeview.py)
  // and the page's CSP forbids inline script, so this is the third of three
  // independent reasons a sample cannot act on the operator -- but it is the
  // one that would be silently undone by a "small" refactor, so it is the one
  // worth a comment.
  var viewer = document.getElementById("loot-viewer");
  var viewerBody = document.getElementById("viewer-body");
  var viewerTitle = document.getElementById("viewer-title");
  var viewerMeta = document.getElementById("viewer-meta");
  var viewerHex = document.getElementById("viewer-hex");
  var viewerText = document.getElementById("viewer-text");
  var viewerStrings = document.getElementById("viewer-strings");
  var current = null;
  var currentMode = "auto";

  // Everything below is one IIFE with the select, re-scan and download
  // handlers, so an addEventListener on a missing element does not fail
  // quietly -- it throws, and every button on the page stops working. That is
  // a far worse outcome than the viewer being absent, and it is exactly what a
  // stale template served from a partly-rebuilt image would cause. Bail
  // instead, leaving the rest of the page intact.
  if (!viewer || !viewerBody || !viewerHex || !viewerText || !viewerStrings) {
    apply();
    return;
  }

  function closeViewer() {
    viewer.hidden = true;
    // Not left in the DOM: a rendered payload sitting in a hidden node is
    // still a rendered payload, and this page stays open for hours.
    viewerBody.textContent = "";
    current = null;
  }

  function load(digest, mode) {
    current = digest;
    currentMode = mode;
    viewer.hidden = false;
    viewerTitle.textContent = digest;
    viewerMeta.textContent = "loading…";
    viewerBody.textContent = "";

    fetch("/api/loot/" + encodeURIComponent(digest) + "/view?mode=" + encodeURIComponent(mode), {
      credentials: "same-origin"
    })
      .then(function (response) { return response.json(); })
      .then(function (body) {
        if (!body.ok) { throw new Error(body.error || "unavailable"); }
        viewerBody.textContent = body.content;

        // Which button is lit has to come from what the server actually did,
        // not from what was asked for: "auto" resolves to text or hex here,
        // and lighting neither leaves the operator unable to tell which view
        // they are reading.
        var resolved = mode === "auto" ? (body.binary ? "hex" : "text") : mode;
        viewerText.classList.toggle("on", resolved === "text");
        viewerStrings.classList.toggle("on", resolved === "strings");
        viewerHex.classList.toggle("on", resolved === "hex");

        // The format label is the useful half of this line. Eleven samples
        // from one dropper differ only by architecture, and "binary" said
        // nothing about which.
        var meta = (body.format || body.kind) + " · " + body.size.toLocaleString() + " B";
        if (body.truncated) {
          meta += (resolved === "strings" ? " · scanned first " : " · showing first ")
                + body.bytes_shown.toLocaleString() + " B";
        }
        if (resolved === "strings" && !body.content) {
          meta += " · no printable runs found";
        }
        viewerMeta.textContent = meta;
      })
      .catch(function (error) {
        viewerMeta.textContent = "";
        viewerBody.textContent = "Could not read this sample: " + error.message;
      });
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-view]");
    if (button) { load(button.getAttribute("data-view"), "auto"); return; }
    if (event.target.id === "viewer-close") { closeViewer(); return; }
    // Clicking the backdrop, but not the panel itself.
    if (event.target === viewer) { closeViewer(); }
  });

  viewerText.addEventListener("click", function () {
    if (current) { load(current, "text"); }
  });
  viewerStrings.addEventListener("click", function () {
    if (current) { load(current, "strings"); }
  });
  viewerHex.addEventListener("click", function () {
    if (current) { load(current, "hex"); }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !viewer.hidden) { closeViewer(); }
  });

  apply();
})();
