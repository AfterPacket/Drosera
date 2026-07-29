// Light/dark theme.
//
// Loaded in <head> WITHOUT defer, on purpose: the stored choice has to be on
// <html> before the first paint, or every page load flashes the default theme
// for a frame before correcting itself.
//
// The preference is a local one -- it belongs to the browser you are reading
// from, not to the operator account -- so it lives in localStorage rather than
// on the server. Nothing about it needs to survive a session, and storing it
// server-side would mean a write on every toggle.
(function () {
  "use strict";

  var KEY = "drosera:theme";
  var root = document.documentElement;

  function stored() {
    try { return window.localStorage.getItem(KEY); } catch (error) { return null; }
  }

  function systemTheme() {
    try {
      return window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light" : "dark";
    } catch (error) {
      return "dark";
    }
  }

  // An explicit choice wins; otherwise follow the OS. Stored as "auto" rather
  // than resolved, so a machine that switches at sunset keeps following along.
  function resolve(preference) {
    return preference === "light" || preference === "dark"
      ? preference : systemTheme();
  }

  function apply(preference) {
    root.setAttribute("data-theme", resolve(preference));
    root.setAttribute("data-theme-pref", preference || "auto");
  }

  apply(stored());

  function set(preference) {
    try {
      if (preference === "auto") {
        window.localStorage.removeItem(KEY);
      } else {
        window.localStorage.setItem(KEY, preference);
      }
    } catch (error) { /* private browsing; the choice just will not persist */ }
    apply(preference);
    label();
    // Charts read their palette from CSS variables and cannot observe a change
    // to them, so they are told to redraw.
    window.dispatchEvent(new CustomEvent("drosera:themechange", {
      detail: { theme: resolve(preference) }
    }));
  }

  var button = null;

  function label() {
    if (!button) { return; }
    var pref = root.getAttribute("data-theme-pref");
    var now = root.getAttribute("data-theme");
    // The icon shows what you would switch TO, which is the convention people
    // already expect from this control.
    button.textContent = now === "light" ? "◓" : "◒";
    button.setAttribute("aria-label",
      "Switch to " + (now === "light" ? "dark" : "light") + " theme"
      + (pref === "auto" ? " (currently following your system setting)" : ""));
    button.title = button.getAttribute("aria-label");
  }

  function toggle() {
    set(root.getAttribute("data-theme") === "light" ? "dark" : "light");
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Only on the operator pages. The login screen is a single centred card and
    // a floating control there is just clutter in front of a password field.
    if (!document.querySelector(".layout")) { return; }

    button = document.createElement("button");
    button.type = "button";
    button.className = "theme-toggle";
    button.addEventListener("click", toggle);
    document.body.appendChild(button);
    label();

    // The Settings page offers the same control with the third option that a
    // one-button toggle cannot express.
    document.querySelectorAll("[data-theme-set]").forEach(function (node) {
      node.addEventListener("click", function () {
        set(node.getAttribute("data-theme-set"));
        markSettings();
      });
    });
    markSettings();
  });

  function markSettings() {
    var pref = root.getAttribute("data-theme-pref");
    document.querySelectorAll("[data-theme-set]").forEach(function (node) {
      var mine = node.getAttribute("data-theme-set") === pref;
      node.classList.toggle("primary", mine);
      node.setAttribute("aria-pressed", mine ? "true" : "false");
    });
  }

  // Following the system means following it live, not only at page load.
  try {
    window.matchMedia("(prefers-color-scheme: light)")
      .addEventListener("change", function () {
        if (root.getAttribute("data-theme-pref") === "auto") {
          apply(null);
          label();
          window.dispatchEvent(new CustomEvent("drosera:themechange",
            { detail: { theme: resolve(null) } }));
        }
      });
  } catch (error) { /* older browsers simply will not track it live */ }

  window.DroseraTheme = { set: set, toggle: toggle };
})();
