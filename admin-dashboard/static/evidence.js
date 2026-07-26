(function () {
  "use strict";

  var button = document.getElementById("copy-all");
  var body = document.getElementById("evidence-body");
  var status = document.getElementById("copy-status");
  if (!button || !body) { return; }

  button.addEventListener("click", function () {
    var text = body.textContent || "";
    function done(ok) {
      if (status) { status.textContent = ok ? "Copied." : "Copy failed."; }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); },
                                              function () { done(false); });
      return;
    }
    // Fallback for non-secure contexts where the async clipboard API is absent.
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "absolute";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (error) { ok = false; }
    document.body.removeChild(area);
    done(ok);
  });
})();
