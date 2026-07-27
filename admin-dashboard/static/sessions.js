// Inline asciinema playback, mounted on demand so we do not load every cast at once.
(function () {
  "use strict";

  document.querySelectorAll("button[data-play]").forEach(function (button) {
    button.addEventListener("click", function () {
      var row = button.closest("tr");
      var next = row ? row.nextElementSibling : null;
      var slot = next ? next.querySelector(".player-slot") : null;
      if (!slot) { return; }

      if (slot.dataset.mounted === "1") {
        window.DroseraCast.stop(slot);
        slot.dataset.mounted = "0";
        button.textContent = "Play";
        return;
      }

      window.DroseraCast.play(button.getAttribute("data-play"), slot);
      slot.dataset.mounted = "1";
      button.textContent = "Hide";
    });
  });

  // Rendered camera clips. Same mount-on-demand approach: a page of autoplaying
  // GIFs would pull tens of megabytes over the operator's SSH tunnel.
  document.querySelectorAll("button[data-clip]").forEach(function (button) {
    button.addEventListener("click", function () {
      var row = button.closest("tr");
      var next = row ? row.nextElementSibling : null;
      var slot = next ? next.querySelector(".clip-slot") : null;
      if (!slot) { return; }

      if (slot.dataset.mounted === "1") {
        slot.textContent = "";
        slot.dataset.mounted = "0";
        button.textContent = "Clip";
        return;
      }

      var source = button.getAttribute("data-clip");
      var element;
      if (button.getAttribute("data-clip-kind") === "video") {
        element = document.createElement("video");
        element.src = source;
        element.controls = true;
        element.loop = true;
        element.autoplay = true;
        element.muted = true;
      } else {
        element = document.createElement("img");
        element.src = source;
        element.alt = "Session clip";
      }
      element.className = "clip-preview";
      slot.textContent = "";
      slot.appendChild(element);
      slot.dataset.mounted = "1";
      button.textContent = "Hide clip";
    });
  });
})();
