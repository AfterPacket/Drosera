// Minimal asciicast v2 player.
//
// Replaces the cdnjs-hosted asciinema-player. That dependency was a poor fit:
// the dashboard is reached over an SSH tunnel from a box with no egress, the
// CSP has to carve out an exception for a third party, and when the CDN does
// not load the only symptom is "Player unavailable" with no explanation.
//
// These recordings are plain terminal output -- a fake shell echoing text -- so
// full terminal emulation buys nothing. This replays frames into a <pre>,
// strips ANSI sequences, and handles the couple of control characters the fake
// shells actually emit.
//
// Because the screen is append-only text rather than an emulated grid, the
// state at any moment is just the concatenation of every frame up to it. That
// is what makes seeking possible here at all: there is no terminal to rewind,
// so a scrub is a substring. A stitched engagement runs to tens of minutes, and
// a recording you can only watch from the start is one nobody watches twice.
(function () {
  "use strict";

  var ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\x07/g;
  var MAX_GAP = 2.0;      // squeeze dead air, same as the renderer
  var MAX_CHARS = 200000; // a tarpitted session can be large; cap the DOM
  var TICK = 100;         // ms between clock ticks

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

  function clock(seconds) {
    seconds = Math.max(0, Math.round(seconds));
    var m = Math.floor(seconds / 60);
    var s = seconds % 60;
    return m + ":" + (s < 10 ? "0" : "") + s;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text) { node.textContent = text; }
    return node;
  }

  function Player(url, slot) {
    this.url = url;
    this.slot = slot;
    this.timer = null;
    this.stopped = false;
    this.playing = false;
    this.speed = 1;
    this.time = 0;      // display-clock seconds
    this.cursor = 0;    // frames drawn so far
    this.frames = [];
    this.text = [];     // cleaned frame payloads, parallel to frames
    this.at = [];       // display-clock time of each frame
    this.total = 0;
  }

  Player.prototype.stop = function () {
    this.stopped = true;
    this.pause();
  };

  Player.prototype.pause = function () {
    this.playing = false;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    if (this.playBtn) {
      this.playBtn.textContent = "▶";
      this.playBtn.setAttribute("aria-label", "Play");
    }
  };

  Player.prototype.play = function () {
    if (this.playing || !this.frames.length) { return; }
    // Replaying from the end should start over rather than sit there.
    if (this.time >= this.total) { this.seek(0); }
    this.playing = true;
    if (this.playBtn) {
      this.playBtn.textContent = "❚❚";
      this.playBtn.setAttribute("aria-label", "Pause");
    }
    var self = this;
    this.timer = setInterval(function () {
      self.time += (TICK / 1000) * self.speed;
      if (self.time >= self.total) {
        self.time = self.total;
        self.draw();
        self.pause();
        return;
      }
      self.draw();
    }, TICK);
  };

  Player.prototype.toggle = function () {
    if (this.playing) { this.pause(); } else { this.play(); }
  };

  // Jump the clock. Redraws from scratch when moving backwards, because the
  // screen is built by appending and there is nothing to un-append.
  Player.prototype.seek = function (seconds) {
    this.time = Math.min(Math.max(seconds, 0), this.total);
    var target = 0;
    while (target < this.at.length && this.at[target] <= this.time) { target++; }
    if (target < this.cursor) {
      this.cursor = 0;
      this.screen.textContent = "";
    }
    this.draw();
  };

  Player.prototype.draw = function () {
    var pending = [];
    while (this.cursor < this.at.length && this.at[this.cursor] <= this.time) {
      pending.push(this.text[this.cursor]);
      this.cursor++;
    }
    if (pending.length) {
      var body = this.screen.textContent + pending.join("");
      // Keep the tail: what is on screen now matters more than what scrolled
      // off, and an unbounded <pre> is what makes a long session unusable.
      if (body.length > MAX_CHARS) { body = body.slice(body.length - MAX_CHARS); }
      this.screen.textContent = body;
      this.screen.scrollTop = this.screen.scrollHeight;
    }
    if (this.scrub) { this.scrub.value = String(this.time); }
    if (this.readout) {
      this.readout.textContent = clock(this.time) + " / " + clock(this.total);
    }
  };

  Player.prototype.chrome = function () {
    var self = this;
    var bar = el("div", "cast-controls");

    this.playBtn = el("button", "cast-btn", "▶");
    this.playBtn.type = "button";
    this.playBtn.setAttribute("aria-label", "Play");
    this.playBtn.addEventListener("click", function () { self.toggle(); });
    bar.appendChild(this.playBtn);

    this.scrub = document.createElement("input");
    this.scrub.type = "range";
    this.scrub.className = "cast-scrub";
    this.scrub.min = "0";
    this.scrub.step = "0.1";
    this.scrub.max = String(this.total);
    this.scrub.value = "0";
    this.scrub.setAttribute("aria-label", "Seek");
    this.scrub.addEventListener("input", function () {
      self.seek(Number(self.scrub.value));
    });
    bar.appendChild(this.scrub);

    this.readout = el("span", "cast-time", "0:00 / " + clock(this.total));
    bar.appendChild(this.readout);

    var speed = document.createElement("select");
    speed.className = "cast-speed";
    speed.setAttribute("aria-label", "Playback speed");
    [1, 2, 4, 8].forEach(function (rate) {
      var option = document.createElement("option");
      option.value = String(rate);
      option.textContent = rate + "×";
      speed.appendChild(option);
    });
    speed.addEventListener("change", function () {
      self.speed = Number(speed.value) || 1;
    });
    bar.appendChild(speed);

    return bar;
  };

  Player.prototype.start = function () {
    var self = this;
    this.slot.textContent = "";

    var screen = el("pre", "cast-screen");
    screen.setAttribute("tabindex", "0");
    screen.setAttribute("role", "log");
    this.screen = screen;

    var status = el("div", "cast-status", "loading…");
    this.status = status;

    this.slot.appendChild(screen);
    this.slot.appendChild(status);

    // Space toggles while the screen has focus, which is the shortcut anyone
    // reaches for; it must not steal the key from the page at large.
    screen.addEventListener("keydown", function (event) {
      if (event.key === " " || event.key === "k") {
        event.preventDefault();
        self.toggle();
      } else if (event.key === "ArrowLeft") {
        event.preventDefault();
        self.seek(self.time - 5);
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        self.seek(self.time + 5);
      }
    });

    fetch(this.url, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) { throw new Error("http " + response.status); }
        return response.text();
      })
      .then(function (body) {
        if (self.stopped) { return; }
        self.frames = parse(body);
        if (!self.frames.length) {
          status.textContent = "recording contains no output";
          return;
        }

        // Recording time -> display time, with dead air squeezed. Done once so
        // that seeking is a lookup rather than a re-walk of every frame.
        var elapsed = 0;
        var previous = 0;
        self.frames.forEach(function (frame) {
          elapsed += Math.min(Math.max(frame[0] - previous, 0), MAX_GAP);
          previous = frame[0];
          self.at.push(elapsed);
          self.text.push(clean(frame[1]));
        });
        self.total = elapsed;

        status.textContent = "";
        status.appendChild(self.chrome());
        self.play();
      })
      .catch(function (error) {
        status.textContent = "could not load recording: " + error.message;
      });
  };

  // ------------------------------------------------------------- follow mode

  // `tail -f` for a recording that is still being written.
  //
  // Replaying a live session with its original timing is not watching it: a
  // connection that opened five minutes ago would take five minutes of replay
  // to reach the present, by which point it is no longer the present. So this
  // renders everything already recorded at once -- catching up instantly --
  // and then appends new frames as they land.
  //
  // It re-reads the whole file each poll rather than requesting a byte range.
  // Recordings are capped at MAX_SESSION_BYTES (2MB by default), the file is
  // local to the container serving it, and a Range request against a file
  // being appended to is the kind of thing that works until it does not.
  function Follower(url, slot) {
    this.url = url;
    this.slot = slot;
    this.rendered = 0;
    this.timer = null;
    this.stopped = false;
    this.idle = 0;
  }

  Follower.prototype.stop = function () {
    this.stopped = true;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  };

  Follower.prototype.tick = function () {
    var self = this;
    fetch(this.url, { credentials: "same-origin", cache: "no-store" })
      .then(function (response) {
        if (!response.ok) { throw new Error("http " + response.status); }
        return response.text();
      })
      .then(function (body) {
        if (self.stopped) { return; }
        var frames = parse(body);
        if (frames.length > self.rendered) {
          var fresh = frames.slice(self.rendered).map(function (f) {
            return clean(f[1]);
          }).join("");
          var text = self.screen.textContent + fresh;
          if (text.length > MAX_CHARS) { text = text.slice(text.length - MAX_CHARS); }
          self.screen.textContent = text;
          self.screen.scrollTop = self.screen.scrollHeight;
          self.rendered = frames.length;
          self.idle = 0;
        } else {
          self.idle += 1;
        }
        self.status.textContent = self.idle > 20
          ? "idle · " + self.rendered + " frames · still following"
          : "following live · " + self.rendered + " frames";
      })
      .catch(function (error) {
        // A recording that has been rotated away or a session that ended is
        // not an error worth shouting about; keep the transcript on screen.
        self.status.textContent = "no longer following: " + error.message;
        self.stop();
      });
  };

  Follower.prototype.start = function () {
    this.slot.textContent = "";
    this.screen = el("pre", "cast-screen");
    this.screen.setAttribute("role", "log");
    this.screen.setAttribute("aria-live", "polite");
    this.status = el("div", "cast-status", "connecting…");
    this.slot.appendChild(this.screen);
    this.slot.appendChild(this.status);

    var self = this;
    this.tick();
    this.timer = setInterval(function () { self.tick(); }, 2000);
  };

  window.DroseraCast = {
    play: function (url, slot) {
      var player = new Player(url, slot);
      slot._drosera = player;
      player.start();
      return player;
    },
    // Catches up instantly, then appends new output as it is written. Use for
    // a session that is still open; use play() for one that has finished.
    follow: function (url, slot) {
      var follower = new Follower(url, slot);
      slot._drosera = follower;
      follower.start();
      return follower;
    },
    stop: function (slot) {
      if (slot && slot._drosera) { slot._drosera.stop(); slot._drosera = null; }
      if (slot) { slot.textContent = ""; }
    }
  };
})();
