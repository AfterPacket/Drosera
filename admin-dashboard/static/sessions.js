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
        slot.textContent = "";
        slot.dataset.mounted = "0";
        button.textContent = "Play";
        return;
      }

      if (typeof window.AsciinemaPlayer === "undefined") {
        slot.textContent = "Player unavailable.";
        return;
      }
      try {
        window.AsciinemaPlayer.create(button.getAttribute("data-play"), slot, {
          fit: "width", speed: 1, idleTimeLimit: 3, theme: "asciinema"
        });
        slot.dataset.mounted = "1";
        button.textContent = "Hide";
      } catch (error) {
        slot.textContent = "Unable to load recording.";
      }
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
