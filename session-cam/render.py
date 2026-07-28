"""asciicast v2 -> animated GIF, with a security-camera overlay.

Pure Python on purpose. Rendering with `agg` or ffmpeg would mean fetching a
binary at build time, and this container is the one piece of the appliance that
is allowed to reach the internet -- keeping its toolchain small keeps that
exposure small. pyte does the terminal emulation, Pillow rasterises.

Everything in a .cast came from an attacker, so nothing here interprets it as
anything but text: pyte resolves escape sequences into a character grid, and we
only ever *write* image data, never decode any.
"""

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pyte
from PIL import Image, ImageDraw, ImageFont

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
]

FONT_SIZE = int(os.getenv("CAM_FONT_SIZE", "14"))
PAD = 10
HUD_TOP = 26
HUD_BOTTOM = 22

# A tarpitted session can idle for half an hour. Real elapsed time is preserved
# in the HUD clock; the clip itself squeezes dead air so it stays watchable.
MAX_IDLE_SECONDS = float(os.getenv("CAM_MAX_IDLE_SECONDS", "2.0"))
MIN_FRAME_INTERVAL = float(os.getenv("CAM_MIN_FRAME_INTERVAL", "0.10"))

# 0 means no cap: render every frame the session produced. That is the default
# now, because sampling to a fixed budget silently dropped the middle of any
# long session -- exactly the part worth watching -- and the clip gave no sign
# that it had. What squeezing remains is MAX_IDLE_SECONDS above, which removes
# silence rather than content and leaves the HUD clock telling the truth.
#
# The cost is a large intermediate GIF, which is why cam.py caps this when the
# GIF is what gets delivered. Through ffmpeg it is a temporary file on the way
# to an MP4 a fraction of its size.
MAX_FRAMES = int(os.getenv("CAM_MAX_FRAMES", "0"))
# Applied only when the GIF itself is the delivered artefact, so a full render
# can never push it past CAM_MAX_CLIP_MB and out of the delivery path entirely.
GIF_SAFETY_FRAMES = int(os.getenv("CAM_GIF_SAFETY_FRAMES", "420"))
TAIL_HOLD_MS = 1500

# A bot that connects, reads the prompt and leaves does all of it inside one
# second, which is faithfully rendered as frames 20ms apart -- accurate and
# completely unwatchable. Stretch clips shorter than this to a legible pace.
# Only short clips are touched; a real session keeps its true timing.
MIN_CLIP_MS = int(os.getenv("CAM_MIN_CLIP_MS", "2500"))

BG = (12, 14, 18)
FG_DEFAULT = (208, 214, 222)
HUD_BG = (24, 26, 32)
HUD_FG = (150, 158, 170)
REC_RED = (226, 62, 62)
ACCENT = (232, 178, 58)

PALETTE = {
    "default": FG_DEFAULT,
    "black": (40, 44, 52),
    "red": (224, 74, 74),
    "green": (126, 192, 80),
    "brown": (215, 168, 60),
    "yellow": (215, 168, 60),
    "blue": (92, 148, 232),
    "magenta": (198, 120, 221),
    "cyan": (86, 182, 194),
    "white": (208, 214, 222),
    "brightblack": (92, 99, 112),
    "brightred": (240, 113, 113),
    "brightgreen": (152, 210, 110),
    "brightbrown": (232, 196, 96),
    "brightyellow": (232, 196, 96),
    "brightblue": (130, 176, 255),
    "brightmagenta": (214, 154, 233),
    "brightcyan": (120, 208, 218),
    "brightwhite": (245, 247, 250),
}


class CastError(Exception):
    """Raised when a .cast is unusable -- malformed, empty, or truncated."""


def _load_font(bold: bool = False) -> Any:
    for path in FONT_CANDIDATES:
        if bold != path.endswith("-Bold.ttf"):
            continue
        if Path(path).is_file():
            try:
                return ImageFont.truetype(path, FONT_SIZE)
            except OSError:
                continue
    for path in FONT_CANDIDATES:
        if Path(path).is_file():
            try:
                return ImageFont.truetype(path, FONT_SIZE)
            except OSError:
                continue
    return ImageFont.load_default()


def _colour(value: Any, fallback: Tuple[int, int, int]) -> Tuple[int, int, int]:
    """pyte hands back either a colour name or a 256-colour 'rrggbb' string."""
    if not value or value == "default":
        return fallback
    name = str(value).lower()
    if name in PALETTE:
        return PALETTE[name]
    if len(name) == 6:
        try:
            return (int(name[0:2], 16), int(name[2:4], 16), int(name[4:6], 16))
        except ValueError:
            pass
    return fallback


def parse_cast(path: Path) -> Tuple[Dict[str, Any], List[Tuple[float, str]]]:
    """Read an asciicast v2 file into (header, [(offset, output_data)]).

    Input frames are dropped: every service that records also echoes keystrokes
    back as output, so replaying both would double every character the attacker
    typed.
    """
    header: Dict[str, Any] = {}
    events: List[Tuple[float, str]] = []

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                # A session killed mid-write leaves a partial final line. Keep
                # what we have rather than losing the whole recording.
                continue
            if index == 0 and isinstance(parsed, dict):
                header = parsed
                continue
            if isinstance(parsed, list) and len(parsed) >= 3 and parsed[1] == "o":
                try:
                    events.append((float(parsed[0]), str(parsed[2])))
                except (TypeError, ValueError):
                    continue

    if not header:
        raise CastError(f"{path.name}: no asciicast header")
    if not events:
        raise CastError(f"{path.name}: no output frames")
    return header, events


def _plan_frames(events: Sequence[Tuple[float, str]], max_frames: int) -> float:
    """Choose a sampling interval that keeps the clip under `max_frames`.

    With no cap the interval is the floor, so every event that changes the
    screen gets a frame and the playback is the session rather than a summary
    of it.
    """
    if max_frames <= 0:
        return MIN_FRAME_INTERVAL
    total = 0.0
    previous = 0.0
    for offset, _ in events:
        total += min(max(offset - previous, 0.0), MAX_IDLE_SECONDS)
        previous = offset
    if total <= 0:
        return MIN_FRAME_INTERVAL
    return max(MIN_FRAME_INTERVAL, total / max_frames)


def _rows(screen: "pyte.Screen") -> List[List[Tuple[str, Any]]]:
    """Snapshot the character grid as [row][ (text_run, char_style) ]."""
    out = []
    for y in range(screen.lines):
        row = screen.buffer[y]
        runs: List[Tuple[str, Any]] = []
        current = ""
        style = None
        for x in range(screen.columns):
            char = row[x]
            key = (char.fg, char.bg, char.bold, char.reverse)
            if style is not None and key == style[0]:
                current += char.data
            else:
                if style is not None:
                    runs.append((current, style[1]))
                current = char.data
                style = (key, char)
        if style is not None:
            runs.append((current, style[1]))
        out.append(runs)
    return out


class Renderer:
    def __init__(self, columns: int, lines: int, meta: Dict[str, Any]):
        self.columns = columns
        self.lines = lines
        self.meta = meta
        self.font = _load_font(bold=False)
        self.font_bold = _load_font(bold=True)
        self.hud_font = self.font

        try:
            self.cw = int(round(self.font.getlength("M"))) or 8
        except AttributeError:
            self.cw = 8
        try:
            ascent, descent = self.font.getmetrics()
            self.ch = ascent + descent
        except AttributeError:
            self.ch = FONT_SIZE + 4

        self.width = self.columns * self.cw + PAD * 2
        self.height = self.lines * self.ch + PAD * 2 + HUD_TOP + HUD_BOTTOM
        self._palette_image = self._build_palette()

    def _build_palette(self) -> Image.Image:
        """A fixed palette keeps every GIF frame on the same colour table, which
        both removes inter-frame flicker and keeps the file small."""
        colours = [BG, FG_DEFAULT, HUD_BG, HUD_FG, REC_RED, ACCENT]
        colours.extend(PALETTE.values())
        unique: List[Tuple[int, int, int]] = []
        for colour in colours:
            if colour not in unique:
                unique.append(colour)
        flat: List[int] = []
        for colour in unique:
            flat.extend(colour)
        flat.extend([0] * (768 - len(flat)))
        image = Image.new("P", (1, 1))
        image.putpalette(flat)
        return image

    def _draw_hud(self, draw: ImageDraw.ImageDraw, elapsed: float,
                  truncated: bool) -> None:
        draw.rectangle([0, 0, self.width, HUD_TOP], fill=HUD_BG)
        draw.rectangle([0, self.height - HUD_BOTTOM, self.width, self.height],
                       fill=HUD_BG)

        # Blink the record dot roughly once a second, like a real camera.
        if int(elapsed) % 2 == 0:
            draw.ellipse([PAD, HUD_TOP // 2 - 5, PAD + 10, HUD_TOP // 2 + 5],
                         fill=REC_RED)
        draw.text((PAD + 18, HUD_TOP // 2 - self.ch // 2), "REC", font=self.hud_font,
                  fill=REC_RED)

        ip = str(self.meta.get("ip", "unknown"))
        service = str(self.meta.get("service", "?")).upper()
        draw.text((PAD + 54, HUD_TOP // 2 - self.ch // 2), f"{ip}  ·  {service}",
                  font=self.hud_font, fill=(226, 230, 236))

        started = str(self.meta.get("started_at", ""))[:19].replace("T", " ")
        clock = f"{started}Z  +{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        try:
            clock_width = int(self.hud_font.getlength(clock))
        except AttributeError:
            clock_width = len(clock) * self.cw
        draw.text((self.width - PAD - clock_width, HUD_TOP // 2 - self.ch // 2),
                  clock, font=self.hud_font, fill=HUD_FG)

        score = self.meta.get("score")
        tool = self.meta.get("tool") or "none"
        host = self.meta.get("fake_hostname") or "-"
        left = f"score {score if score is not None else '-'}  ·  tool {tool}  ·  as {host}"
        if self.meta.get("banned"):
            left += "  ·  BANNED"
        elif self.meta.get("tarpit_active"):
            left += "  ·  TARPITTED"
        baseline = self.height - HUD_BOTTOM + (HUD_BOTTOM - self.ch) // 2
        draw.text((PAD, baseline), left, font=self.hud_font, fill=HUD_FG)

        label = "DROSERA CAM" + ("  ·  TRUNCATED" if truncated else "")
        try:
            label_width = int(self.hud_font.getlength(label))
        except AttributeError:
            label_width = len(label) * self.cw
        draw.text((self.width - PAD - label_width, baseline), label,
                  font=self.hud_font, fill=ACCENT if truncated else HUD_FG)

    def frame(self, screen: "pyte.Screen", elapsed: float,
              truncated: bool) -> Image.Image:
        image = Image.new("RGB", (self.width, self.height), BG)
        draw = ImageDraw.Draw(image)
        self._draw_hud(draw, elapsed, truncated)

        top = PAD + HUD_TOP
        for y, runs in enumerate(_rows(screen)):
            x = PAD
            for text, char in runs:
                run_width = len(text) * self.cw
                fg = _colour(char.fg, FG_DEFAULT)
                bg = _colour(char.bg, BG)
                if char.reverse:
                    fg, bg = bg, fg
                if bg != BG:
                    draw.rectangle([x, top + y * self.ch,
                                    x + run_width, top + (y + 1) * self.ch], fill=bg)
                if text.strip():
                    draw.text((x, top + y * self.ch), text,
                              font=self.font_bold if char.bold else self.font, fill=fg)
                x += run_width
        return image

    def quantize(self, image: Image.Image) -> Image.Image:
        try:
            return image.quantize(palette=self._palette_image, dither=Image.Dither.NONE)
        except (AttributeError, ValueError):
            return image.convert("P", palette=Image.ADAPTIVE, colors=64)


def render_gif(cast_path: Path, out_path: Path,
               meta: Optional[Dict[str, Any]] = None,
               max_frames: Optional[int] = None) -> Path:
    """Render a .cast to an animated GIF. Returns the written path.

    `max_frames` overrides CAM_MAX_FRAMES; 0 or below means every frame. The
    caller decides, because the right answer depends on whether this GIF is the
    artefact being delivered or an intermediate on the way to an MP4.
    """
    meta = dict(meta or {})
    budget = MAX_FRAMES if max_frames is None else max_frames
    header, events = parse_cast(cast_path)

    columns = int(meta.get("width") or header.get("width") or 80)
    lines = int(meta.get("height") or header.get("height") or 24)
    columns = max(20, min(columns, 200))
    lines = max(5, min(lines, 60))

    if not meta.get("started_at"):
        stamp = header.get("timestamp")
        if stamp:
            meta["started_at"] = datetime.fromtimestamp(
                int(stamp), timezone.utc).isoformat()

    screen = pyte.Screen(columns, lines)
    stream = pyte.Stream(screen)
    renderer = Renderer(columns, lines, meta)
    interval = _plan_frames(events, budget)

    # (image, virtual timestamp). Durations are diffs taken afterwards, since a
    # GIF frame's duration is the gap until the *next* frame.
    shots: List[Tuple[Image.Image, float]] = []

    virtual = 0.0        # squeezed clock, drives GIF frame delays
    real = 0.0           # true session clock, shown in the HUD
    previous = 0.0
    last_emit = -interval
    truncated = bool(meta.get("truncated"))

    for offset, data in events:
        gap = max(offset - previous, 0.0)
        virtual += min(gap, MAX_IDLE_SECONDS)
        real = offset
        previous = offset

        try:
            stream.feed(data)
        except Exception:
            # Malformed escape sequences are attacker-controlled and expected.
            continue

        if virtual - last_emit >= interval and (budget <= 0 or len(shots) < budget):
            shots.append((renderer.quantize(renderer.frame(screen, real, truncated)),
                          virtual))
            last_emit = virtual

    # Always end on the final state, whether or not the cap was hit.
    shots.append((renderer.quantize(renderer.frame(screen, real, truncated)), virtual))

    if not shots:
        raise CastError(f"{cast_path.name}: produced no frames")

    frames = [shot for shot, _ in shots]
    delays = []
    for index in range(len(shots) - 1):
        delays.append(max(int((shots[index + 1][1] - shots[index][1]) * 1000), 20))
    delays.append(TAIL_HOLD_MS)

    # Raise the floor on clips that would otherwise flash past. The tail hold is
    # excluded from the measurement and left alone, so the final frame still
    # lingers long enough to read.
    body = sum(delays[:-1])
    if len(delays) > 1 and body < MIN_CLIP_MS:
        floor = MIN_CLIP_MS // (len(delays) - 1)
        delays = [max(delay, floor) for delay in delays[:-1]] + [delays[-1]]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        duration=delays,
        loop=0,
        optimize=True,
        disposal=1,
    )
    return out_path


def have_ffmpeg() -> bool:
    """Whether an MP4 can be produced at all.

    Asked before rendering, not after: the frame budget depends on whether the
    GIF is a deliverable or a temporary file, and that is decided by this.
    """
    return shutil.which("ffmpeg") is not None


def render_mp4(gif_path: Path, out_path: Path) -> Optional[Path]:
    """Transcode to MP4 when ffmpeg is available. Returns None when it is not.

    MP4 is worth having where it exists: Telegram plays it inline and it is
    several times smaller than the equivalent GIF for a long session.
    """
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return None
    try:
        subprocess.run(
            [ffmpeg, "-y", "-loglevel", "error", "-i", str(gif_path),
             "-movflags", "faststart", "-pix_fmt", "yuv420p",
             # H.264 needs even dimensions; GIF sizes are arbitrary.
             "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
             str(out_path)],
            check=True, timeout=180, stdin=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out_path if out_path.is_file() else None
