// Minimal asciicast v2 player.
//
// Replaces the cdnjs-hosted asciinema-player. That dependency was a poor fit:
// the dashboard is reached over an SSH tunnel from a box with no egress, the
// CSP has to carve out an exception for a third party, and when the CDN does
// not load the only symptom is "Player unavailable" with no explanation.
//
// These recordings are plain terminal output -- a fake shell echoing text --
// so full terminal emulation buys nothing. This replays frames into a <pre>
// with the original timing, strips ANSI sequences, and handles the couple of
// control characters the fake shells actually emit.
(function () {
  "use strict";

  var ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\x07/g;
  var MAX_GAP = 2.0;      // squeeze dead air, same as the renderer
  var MAX_CHARS = 200000; // a tarpitted session can be large; cap the DOM

  function clean(text) {
    return String(text)
      .replace(ANSI, "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n");
  }

  function parse(body) {
    var lines = body.split("\n");
    var frames = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) { continue; }
      var parsed;
      try { parsed = JSON.parse(line); } catch (error) { continue; }
      // Index 0 is the header object; frames are [offset, stream, data].
      // Input frames are skipped: the shells echo keystrokes back as output,
      // so replaying both would double every character the attacker typed.
      if (Array.isArray(parsed) && parsed.length >= 3 && parsed[1] === "o") {
        frames.push([Number(parsed[0]) || 0, String(parsed[2])]);
      }
    }
    return frames;
  }

  function Player(url, slot) {
    this.url = url;
    this.slot = slot;
    this.timer = null;
    this.stopped = false;
  }

  Player.prototype.stop = function () {
    this.stopped = true;
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
  };

  Player.prototype.start = function () {
    var self = this;
    this.slot.textContent = "";

    var screen = document.createElement("pre");
    screen.className = "cast-screen";
    this.slot.appendChild(screen);

    var status = document.createElement("div");
    status.className = "cast-status";
    status.textContent = "loading…";
    this.slot.appendChild(status);

    fetch(this.url, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) { throw new Error("http " + response.status); }
        return response.text();
      })
      .then(function (body) {
        var frames = parse(body);
        if (!frames.length) {
          status.textContent = "recording contains no output";
          return;
        }

        var index = 0;
        var previous = 0;

        function step() {
          if (self.stopped || index >= frames.length) {
            if (!self.stopped) {
              var seconds = frames[frames.length - 1][0];
              status.textContent = "end of recording · "
                + seconds.toFixed(1) + "s · " + frames.length + " frames";
            }
            return;
          }
          var frame = frames[index++];
          if (screen.textContent.length < MAX_CHARS) {
            screen.textContent += clean(frame[1]);
          }
          screen.scrollTop = screen.scrollHeight;
          status.textContent = "playing · " + frame[0].toFixed(1) + "s";

          var gap = Math.min(Math.max(frame[0] - previous, 0), MAX_GAP);
          previous = frame[0];
          self.timer = setTimeout(step, gap * 1000);
        }
        step();
      })
      .catch(function (error) {
        status.textContent = "could not load recording: " + error.message;
      });
  };

  window.DroseraCast = {
    play: function (url, slot) {
      var player = new Player(url, slot);
      slot._drosera = player;
      player.start();
      return player;
    },
    stop: function (slot) {
      if (slot && slot._drosera) { slot._drosera.stop(); slot._drosera = null; }
      if (slot) { slot.textContent = ""; }
    }
  };
})();
