"""Simulated bash session.

Zero-trust: nothing here shells out, evaluates, or touches a real path. Every
command is matched against a table and answered from the fake identity's
in-Redis filesystem. Unknown commands get a plausible bash error.

Latency tiers mimic real work so an attacker's timing heuristics agree with the
story the rest of the honeypot tells.
"""

import os
import random
import re
import shlex
import time
import zlib

from . import loot, persona
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

FAST = 0.0
MEDIUM = 0.15
SLOW_MIN, SLOW_MAX = 1.5, 3.0

# The same eight commands appearing in .bash_history on two unrelated hosts
# tells an attacker exactly what both of them are, so this comes from the
# deployment's persona.
SEEDED_HISTORY = persona.pool("seeded_history")

# The "admin workstation" that shows up in netstat, journalctl, w, last and the
# SSH motd. It has to be the same address in all of them -- an attacker who
# compares them is checking exactly this -- and it has to differ per deployment.
ADMIN_IP = persona.get("last_login_from")

# `nmap` in the fake shell reports on the attacker's own address instead of the
# target they gave. It is unnerving and it costs them time, but it also tells a
# careful attacker that the box is watching them, which ends the session and the
# intel it was producing. Set HONEYPOT_SCANBACK=0 to keep them talking instead.
SCANBACK = os.getenv("HONEYPOT_SCANBACK", "1") not in ("0", "false", "no", "")

# Plausible ports to report on a random internet host: a compromised VPS, a
# home router, someone else's poorly-kept box. Chosen deterministically per
# address so the same attacker rescanning gets the same answer.
SCANBACK_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "domain"),
    (80, "http"), (110, "pop3"), (143, "imap"), (443, "https"),
    (445, "microsoft-ds"), (993, "imaps"), (995, "pop3s"), (1723, "pptp"),
    (3306, "mysql"), (3389, "ms-wbt-server"), (5900, "vnc"), (8080, "http-proxy"),
    (8443, "https-alt"),
]

CRONTAB = """# m h  dom mon dow   command
*/5 * * * * /usr/bin/php /opt/monitoring/check.php > /dev/null 2>&1
0 2 * * * /usr/local/bin/backup.sh > /var/log/backup.log 2>&1
30 3 * * 0 apt-get -qq update && apt-get -qq -y upgrade > /dev/null 2>&1"""

REVERSE_SHELL_PATTERNS = re.compile(
    r"(/dev/tcp/|nc\s+-[a-z]*e|ncat\s|socat\s|bash\s+-i|sh\s+-i|"
    r"python[23]?\s+-c.*socket|perl\s+-e.*socket|php\s+-r.*fsockopen|"
    r"mkfifo|telnet\s+\d+\.\d+\.\d+\.\d+\s+\d+|curl.*\|\s*(ba)?sh|"
    r"wget.*\|\s*(ba)?sh|base64\s+-d.*\|\s*(ba)?sh)",
    re.IGNORECASE,
)

HOST_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,})[\s:/]+(\d{2,5})", re.I)

DROPPED_BINARY_RE = re.compile(r"(?:^|&&|;|\|)\s*(\./[\w.\-]+)")


def split_stages(line: str):
    """Split a command line on `;`, `&&`, `||` and newlines.

    Returns [(operator_before_this_stage, stage)], where the operator is "" for
    the first stage. Separators inside quotes are ignored, so
    `echo "a; b"` stays one command.

    Pipes are deliberately NOT split: `ps aux | grep x` is a single pipeline,
    and the handlers already accept the remainder as arguments. Splitting it
    would produce a bogus second command.
    """
    stages = []
    buffer = ""
    operator = ""
    quote = None
    depth = 0          # inside $( ) or ( )
    backtick = False
    index = 0

    while index < len(line):
        char = line[index]

        if quote:
            buffer += char
            if char == quote:
                quote = None
            index += 1
            continue

        if char in "\"'":
            quote = char
            buffer += char
            index += 1
            continue

        # A separator inside a command substitution belongs to the inner
        # command, not to us. Fingerprinting scripts lean on this constantly:
        #   uname=$(uname -m || busybox uname -m || echo "")
        # Splitting that on || produces three nonsense fragments.
        if char == "`":
            backtick = not backtick
            buffer += char
            index += 1
            continue

        if char == "(":
            depth += 1
            buffer += char
            index += 1
            continue

        if char == ")" and depth > 0:
            depth -= 1
            buffer += char
            index += 1
            continue

        if depth or backtick:
            buffer += char
            index += 1
            continue

        if line[index:index + 2] in ("&&", "||"):
            stages.append((operator, buffer.strip()))
            operator = line[index:index + 2]
            buffer = ""
            index += 2
            continue

        if char in ";\n":
            stages.append((operator, buffer.strip()))
            operator = ";"
            buffer = ""
            index += 1
            continue

        buffer += char
        index += 1

    stages.append((operator, buffer.strip()))
    return [(op, stage) for op, stage in stages if stage]


def scan_redirects(stage: str):
    """Strip redirections that are outside quotes.

    Returns (cleaned_stage, operator, target); operator and target are None
    when the stage redirects nothing to stdout.

    Quote-awareness is the entire point. A plain regex substitution reached
    inside `bash -c 'printf ... > filter && ./filter'` and deleted the inner
    `> filter`, so the script the attacker asked us to run lost the write it
    depended on, `./filter` found nothing, and their capability probe failed --
    which is the moment a worm gives up and never drops the real payload.

    Only `>` and `>>` to a filename are reported. `2>/dev/null` and `2>&1` are
    noise suppression and are removed without being mistaken for a file write.
    """
    kept = []
    operator = target = None
    quote = None
    index = 0
    last = 0
    length = len(stage)

    while index < length:
        char = stage[index]

        if quote:
            if char == "\\" and quote == '"' and index + 1 < length:
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue

        if char in ("'", '"'):
            quote = char
            index += 1
            continue

        if char != ">":
            index += 1
            continue

        # A single digit immediately before the `>` is a file descriptor, but
        # only when it stands alone: in `echo abc1> f` the 1 is part of the
        # word, and bash writes "abc1". Requiring whitespace or start-of-stage
        # in front of it is what separates the two.
        start = index
        descriptor = ""
        if (index - 1 >= last and stage[index - 1].isdigit()
                and (index - 2 < last or stage[index - 2].isspace())):
            descriptor = stage[index - 1]
            start = index - 1

        cursor = index + 1
        this_operator = ">"
        if cursor < length and stage[cursor] == ">":
            this_operator = ">>"
            cursor += 1

        if cursor < length and stage[cursor] == "&":
            # `2>&1`: a duplication, never a file.
            cursor += 1
            while cursor < length and stage[cursor].isdigit():
                cursor += 1
            kept.append(stage[last:start])
            last = index = cursor
            continue

        while cursor < length and stage[cursor].isspace():
            cursor += 1
        target_start = cursor
        while cursor < length and not stage[cursor].isspace():
            cursor += 1
        this_target = stage[target_start:cursor]

        # First stdout redirection wins, as in a real shell.
        if descriptor in ("", "1") and this_target and target is None:
            operator, target = this_operator, this_target

        kept.append(stage[last:start])
        last = index = cursor

    kept.append(stage[last:])
    return "".join(kept).strip(), operator, target


# Shells, for the wrapper check in _run_stage. `bash -c '<script>'` must be
# dispatched before anything scans the stage for `./payload`, or the pattern
# inside the quoted script matches and the wrapper is never reached.
SHELL_COMMANDS = ("bash", "sh", "dash", "ash", "zsh", "ksh")


class FakeShell:
    """Stateful fake bash for one attacker session."""

    def __init__(self, ip: str, identity: Dict[str, Any],
                 score: Optional[Callable[..., Any]] = None,
                 service: str = "ssh", username: str = "root",
                 sleeper: Optional[Callable[[float], Any]] = None):
        self.ip = ip
        self.identity = identity
        self.service = service
        self.username = username
        self._score = score or (lambda *a, **k: None)
        self._sleep = sleeper or time.sleep
        self.cwd = identity.get("fake_cwd") or "/var/www/html"
        self.history: List[str] = list(SEEDED_HISTORY)
        self.exit_requested = False
        self._scored_once: set = set()
        # Shell variables the attacker sets. Profiling scripts assign the output
        # of a probe to a variable and echo it back later, so without this the
        # whole exchange returns empty and reads as obviously fake.
        self.env: Dict[str, str] = {}
        # Contents of files they have written this session, so that running one
        # back can produce what it would actually have printed.
        self.written: Dict[str, str] = {}
        # Bounds nested `bash -c` and self-invoking scripts. See _run_script.
        self._script_depth = 0

    # ---------------------------------------------------------------- helpers

    @property
    def hostname(self) -> str:
        return self.identity.get("fake_hostname", "srv-01")

    def prompt(self) -> str:
        home = f"/home/{self.username}"
        display = "~" if self.cwd in (home, "/root" if self.username == "root" else home) else self.cwd
        symbol = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{display}{symbol} "

    def _latency(self, tier: str) -> None:
        if tier == "medium":
            self._sleep(MEDIUM)
        elif tier == "slow":
            self._sleep(random.uniform(SLOW_MIN, SLOW_MAX))

    def _score_once(self, event_type: str, payload: str = "") -> None:
        """Recon events fire once per session; abuse events fire every time."""
        if event_type in self._scored_once:
            return
        self._scored_once.add(event_type)
        self._score(self.ip, event_type, payload=payload, service=self.service)

    def _score_always(self, event_type: str, payload: str = "") -> None:
        self._score(self.ip, event_type, payload=payload, service=self.service)

    # ------------------------------------------------------------ filesystem

    def _resolve(self, path: str) -> str:
        if not path:
            return self.cwd
        path = path.strip()
        if path.startswith("~"):
            home = "/root" if self.username == "root" else f"/home/{self.username}"
            path = home + path[1:]
        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path
        parts: List[str] = []
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts)

    def _node(self, path: str) -> Optional[Dict[str, Any]]:
        node = self.identity.get("fake_filesystem") or {}
        resolved = self._resolve(path)
        if resolved == "/":
            return node
        for part in resolved.strip("/").split("/"):
            if node.get("type") != "dir":
                return None
            node = (node.get("children") or {}).get(part)
            if node is None:
                return None
        return node

    def _listing(self, path: str, show_all: bool, long_form: bool) -> str:
        node = self._node(path)
        if node is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if node.get("type") != "dir":
            return path
        children: Dict[str, Any] = node.get("children") or {}
        names = sorted(children)
        if not show_all:
            names = [n for n in names if not n.startswith(".")]
        if not long_form:
            return "  ".join(names)

        stamp = datetime.now(timezone.utc).strftime("%b %e %H:%M")
        lines = [f"total {max(4, len(names) * 4)}"]
        if show_all:
            lines.append(f"drwxr-xr-x  {len(names) + 2} root     root         4096 {stamp} .")
            lines.append(f"drwxr-xr-x  22 root     root         4096 {stamp} ..")
        for name in names:
            child = children[name]
            mode = child.get("mode") or ("drwxr-xr-x" if child.get("type") == "dir" else "-rw-r--r--")
            size = 4096 if child.get("type") == "dir" else int(child.get("size", 0))
            owner = "www-data" if "/var/www" in self._resolve(path) else "root"
            links = len(child.get("children") or {}) + 2 if child.get("type") == "dir" else 1
            lines.append(f"{mode}  {links:>2} {owner:<8} {owner:<8} {size:>10} {stamp} {name}")
        return "\n".join(lines)

    # ------------------------------------------------------------- dispatch

    def run(self, line: str) -> str:
        """Execute one command line. Returns the text to send back to the attacker."""
        line = (line or "").strip()
        if not line:
            return ""
        self.history.append(line)
        self._score_always("WEBSHELL_CMD", payload=line[:200])

        if REVERSE_SHELL_PATTERNS.search(line):
            return self._reverse_shell(line)

        # Bots chain relentlessly -- `cd ~; chattr -ia .ssh; lockr -ia .ssh` is a
        # single line to them. Treating that as one command produced
        # "bash: cd: ~;: No such file or directory", which is both an obvious
        # tell and a loss of data: only the first fragment was ever dispatched,
        # so the interesting part of the payload scored nothing.
        outputs = []
        failed = False
        for operator, stage in split_stages(line):
            if operator == "&&" and failed:
                continue
            if operator == "||" and not failed:
                continue
            result = self._run_stage(stage)
            # No real exit codes here, so approximate: our handlers report
            # failure the way bash does, by leading with "bash:".
            failed = result.startswith("bash:")
            if result:
                outputs.append(result)
        return "\n".join(outputs)

    _ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
    # Redirections are found by scan_redirects(), not a regex: a regex cannot
    # tell a `>` inside `bash -c '... > file ...'` from one that belongs to the
    # stage, and stripping the inner one broke the script it was part of.
    _SUBST_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
    _VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")

    def _expand(self, text: str, depth: int = 0) -> str:
        """Resolve $(...), `...` and $VAR, innermost first.

        Depth-limited: an attacker can nest substitutions arbitrarily, and this
        runs inside their connection, so it must not become a way to spend our
        CPU. Anything deeper than a handful of levels resolves to empty, which
        is also what a failing command would produce.
        """
        if depth > 4:
            return ""

        def substitute(match):
            inner = match.group(1) if match.group(1) is not None else match.group(2)
            # Substitutions commonly contain their own || fallback chain.
            result = ""
            failed = False
            for operator, stage in split_stages(self._expand(inner, depth + 1)):
                if operator == "&&" and failed:
                    continue
                if operator == "||" and not failed:
                    continue
                result = self._run_stage(stage, depth + 1)
                failed = result.startswith("bash:")
                if not failed and result:
                    break
            return "" if failed else result.strip()

        previous = None
        while previous != text and depth <= 4:
            previous = text
            text = self._SUBST_RE.sub(substitute, text)

        return self._VAR_RE.sub(
            lambda m: self.env.get(m.group(1) or m.group(2), ""), text)

    def _write_file(self, path: str, content: str, append: bool) -> None:
        """Pretend a redirection landed, and score what it was carrying.

        Only the fake tree in memory is touched -- nothing reaches a real path,
        here or anywhere else. Writing ~/.ssh/authorized_keys is the payoff of
        the whole persistence chain, and the key itself is directly
        attributable, so it is captured rather than merely counted.
        """
        resolved = self._resolve(path)
        if resolved.startswith("/dev/") or resolved.startswith("/proc/"):
            return

        # Kept so that running the file back can reproduce its output.
        previous = self.written.get(resolved, "") if append else ""
        self.written[resolved] = (previous + content)[:8192]

        # Quarantine it too. A dropper delivered as a heredoc or a base64 blob
        # piped through `base64 -d` never touches SFTP, so this is often the
        # only copy of the payload we get. loot.capture filters out the
        # sub-24-byte capability probes and deduplicates the rest.
        try:
            loot.capture(
                self.written[resolved].encode("utf-8", "replace"),
                ip=self.ip, service=self.service,
                origin="shell-write", filename=resolved,
            )
        except Exception:
            # Capture is a bonus. It must never break the illusion by turning
            # a redirection into a traceback in the attacker's session.
            pass

        lowered = resolved.lower()
        if "authorized_keys" in lowered:
            self._score_always("PERSISTENCE_ATTEMPT",
                               payload=f"{resolved} <- {content[:300]}")
        elif any(name in lowered for name in
                 ("/etc/passwd", "/etc/shadow", "/etc/crontab", "rc.local",
                  "/etc/cron", "/etc/systemd", ".bashrc", ".profile")):
            self._score_always("PERSISTENCE_ATTEMPT",
                               payload=f"{resolved} <- {content[:300]}")

        # Materialise it so a follow-up `ls` or `cat` agrees that the write
        # happened. In-memory for this session only: persisting the tree would
        # mean writing attacker-controlled content back into Redis.
        parts = [p for p in resolved.strip("/").split("/") if p]
        if not parts:
            return
        node = self.identity.get("fake_filesystem")
        if not isinstance(node, dict):
            return
        for part in parts[:-1]:
            children = node.setdefault("children", {})
            child = children.get(part)
            if child is None or child.get("type") != "dir":
                child = {"type": "dir", "mode": "drwxr-xr-x", "children": {}}
                children[part] = child
            node = child
        children = node.setdefault("children", {})
        existing = children.get(parts[-1]) or {}
        size = int(existing.get("size", 0)) if append else 0
        children[parts[-1]] = {
            "type": "file", "mode": "-rw-------",
            "size": size + len(content) + 1,
        }

    def _run_script(self, script: str) -> str:
        """Run a script the attacker wrote, one line at a time.

        Depth is not the concern here -- a script that invokes itself is
        already bounded by the stage recursion limit -- but breadth is: a
        thousand-line drop should not become a thousand dispatches, so only
        the first handful of lines are honoured.
        """
        # Nesting guard. `depth` below only limits the expander; it does not
        # bound this. Without a counter, `bash -c 'bash -c "..."'` and a script
        # that writes and runs itself both recurse until Python's own limit
        # trips, which costs a session and a stack trace for one cheap line of
        # attacker input.
        if self._script_depth >= 4:
            return ""
        self._script_depth += 1
        try:
            return self._run_script_inner(script)
        finally:
            self._script_depth -= 1

    def _run_script_inner(self, script: str) -> str:
        outputs = []
        stages = 0
        for line in script.splitlines()[:20]:
            line = line.strip()
            if not line or line.startswith("#"):
                continue          # shebang and comments
            # Split on `&&`/`;` as well as newlines. A one-line probe is the
            # common shape -- `printf ... > filter && chmod +x filter &&
            # ./filter` -- and running it as a single stage meant the write
            # never happened, so `./filter` had nothing to run.
            failed = False
            for operator, stage in split_stages(line):
                if operator == "&&" and failed:
                    continue
                if operator == "||" and not failed:
                    continue
                stages += 1
                if stages > 40:
                    return "\n".join(outputs)
                # depth=3 caps how far a script that writes and runs another
                # can recurse before the expander refuses to go deeper.
                result = self._run_stage(stage, depth=3)
                failed = result.startswith("bash:")
                if result:
                    outputs.append(result)
        return "\n".join(outputs)

    def _cmd_sh(self, args: List[str], _line: str) -> str:
        """Run `bash -c '<script>'` instead of shrugging at it.

        Worms wrap their whole capability probe in one `bash -c`, so treating
        it as a single opaque stage meant `printf ... > filter && ./filter`
        never wrote anything, `./filter` produced no output, and their
        `case "$out" in *xxxxxx*` check failed. They then disconnect without
        dropping the real payload -- the only part actually worth capturing.
        """
        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "-c":
                if index + 1 < len(args):
                    return self._run_script(args[index + 1])
                return ""
            if arg.startswith("-"):
                index += 1
                continue
            script = self.written.get(self._resolve(arg))
            if script is not None:
                return self._run_script(script)
            return f"bash: {arg}: No such file or directory"
        return ""

    def _run_stage(self, stage: str, depth: int = 0) -> str:
        """Dispatch a single command, with pipes left as arguments to it."""
        # The target is captured, not just discarded. Without it, `echo
        # 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys` echoed the key straight
        # back at the attacker, where a real shell writes it silently -- a
        # plain tell at the exact moment they are deciding whether the box is
        # real. _finish() applies it once the command has produced output.
        stage, redirect_op, redirect_target = scan_redirects(stage)
        if not stage:
            return ""

        # `VAR=$(probe)` -- store it and stay silent, exactly as a shell does.
        assignment = self._ASSIGNMENT_RE.match(stage)
        if assignment and " " not in assignment.group(1):
            self.env[assignment.group(1)] = self._expand(
                assignment.group(2).strip().strip("\"'"), depth)
            return ""

        stage = self._expand(stage, depth)
        if not stage.strip():
            return ""

        try:
            tokens = shlex.split(stage)
        except ValueError:
            tokens = stage.split()

        command = tokens[0].rsplit("/", 1)[-1] if tokens else ""
        args = tokens[1:]
        if command == "busybox" and args:        # busybox uname -m -> uname -m
            command, args = args[0], args[1:]

        # Shell wrappers are dispatched before the dropped-binary scan below.
        # That scan is a regex over the whole stage, so for
        # `bash -c '... && ./filter'` it matched the `./filter` inside the
        # quoted script and answered "Exec format error" without ever running
        # the script -- the wrapper handler could never be reached for the one
        # payload shape it exists to handle.
        if command in SHELL_COMMANDS and args:
            result = self._cmd_sh(args, stage)
            return self._finish(result, redirect_op, redirect_target, depth)

        # Per stage, not per line: `printf ... > filter && ./filter` used to
        # match on the whole line and return one error for everything, so a
        # profiling script got a single "Exec format error" where it expected
        # a dozen answers.
        dropped = DROPPED_BINARY_RE.search(stage)
        if dropped:
            name = dropped.group(1)
            self._score_once("DROPPED_BINARY_EXEC", payload=stage[:300])
            script = self.written.get(self._resolve(name))
            if script is not None:
                # They wrote it here, so we know what it prints. Fingerprinting
                # scripts write a trivial script and run it purely to learn
                # whether this filesystem permits it -- answering correctly is
                # what convinces them to go on and drop the real payload, which
                # is the thing actually worth capturing.
                self._sleep(0.2)
                return self._run_script(script)
            self._sleep(0.5)
            return (f"bash: {name}: cannot execute binary file: "
                    "Exec format error")

        if not tokens:
            return ""

        handler = self._HANDLERS.get(command)
        if handler is None:
            return f"bash: {command}: command not found"

        return self._finish(handler(self, args, stage),
                            redirect_op, redirect_target, depth)

    def _finish(self, result: str, operator, target, depth: int) -> str:
        """Apply a stdout redirection, if the stage had one."""
        if not target:
            return result
        self._write_file(self._expand(target, depth), result or "",
                         append=(operator == ">>"))
        return ""          # a redirected command prints nothing

    # -------------------------------------------------------------- commands

    def _cmd_ls(self, args: List[str], _line: str) -> str:
        self._score_once("RECON_LS")
        self._latency("fast")
        flags = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]
        joined = "".join(flags)
        return self._listing(paths[0] if paths else self.cwd, "a" in joined, "l" in joined)

    @property
    def home(self) -> str:
        return "/root" if self.username == "root" else f"/home/{self.username}"

    def _cmd_cd(self, args: List[str], _line: str) -> str:
        target = args[0] if args else self.home
        # `cd ~` and `cd ~/.ssh` are the opening move of nearly every SSH
        # persistence script. Without tilde expansion they returned "No such
        # file or directory", which ends the intrusion at step one and tells
        # the operator the shell is fake.
        if target == "~":
            target = self.home
        elif target.startswith("~/"):
            target = self.home + target[1:]

        resolved = self._resolve(target)
        node = self._node(resolved)
        if node is None:
            # A real home directory exists even when our fake tree has not
            # materialised it yet.
            if resolved == self.home:
                self.cwd = resolved
                return ""
            return f"bash: cd: {target}: No such file or directory"
        if node.get("type") != "dir":
            return f"bash: cd: {target}: Not a directory"
        self.cwd = resolved
        return ""

    def _cmd_pwd(self, _args: List[str], _line: str) -> str:
        return self.cwd

    def _cmd_cat(self, args: List[str], _line: str) -> str:
        self._latency("fast")
        if not args:
            return ""
        out = []
        for raw in args:
            if raw.startswith("-"):
                continue
            resolved = self._resolve(raw)
            if resolved == "/etc/passwd":
                self._score_once("READ_PASSWD", payload=resolved)
                out.append(self._passwd_file())
            elif resolved == "/etc/shadow":
                self._score_once("READ_SHADOW", payload=resolved)
                out.append(f"cat: {raw}: Permission denied"
                           if self.username != "root" else self._shadow_file())
            elif resolved.endswith("wp-config.php"):
                out.append(self._wp_config())
            elif resolved == "/etc/hostname":
                out.append(self.hostname)
            elif resolved == "/etc/os-release":
                out.append(self._os_release())
            elif resolved == "/etc/crontab":
                out.append(CRONTAB)
            elif resolved.endswith(".bash_history"):
                out.append("\n".join(SEEDED_HISTORY))
            else:
                node = self._node(resolved)
                if node is None:
                    out.append(f"cat: {raw}: No such file or directory")
                elif node.get("type") == "dir":
                    out.append(f"cat: {raw}: Is a directory")
                else:
                    out.append(f"cat: {raw}: Permission denied")
        return "\n".join(out)

    def _cmd_id(self, _args: List[str], _line: str) -> str:
        for user in self.identity.get("fake_users") or []:
            if user["username"] == self.username:
                groups = ",".join(f"{1000 + i}({g})" for i, g in enumerate(user.get("groups", [])))
                return (f"uid={user['uid']}({user['username']}) gid={user['gid']}({user['username']})"
                        + (f" groups={groups}" if groups else ""))
        return "uid=0(root) gid=0(root) groups=0(root)"

    def _cmd_whoami(self, _args: List[str], _line: str) -> str:
        return self.username

    def _cmd_uname(self, args: List[str], _line: str) -> str:
        kernel = self.identity.get("fake_kernel", "5.15.0-86-generic")
        if not args or args == ["-s"]:
            return "Linux"
        if "-r" in args:
            return kernel
        return (f"Linux {self.hostname} {kernel} #1 SMP Debian 5.15.0-86 "
                f"x86_64 x86_64 x86_64 GNU/Linux")

    def _cmd_ps(self, _args: List[str], _line: str) -> str:
        self._score_once("PROCESS_ENUM")
        self._latency("medium")
        return (
            "  PID TTY      STAT   TIME COMMAND\n"
            "    1 ?        Ss     0:04 /sbin/init\n"
            "  412 ?        Ss     0:01 /lib/systemd/systemd-journald\n"
            "  689 ?        Ss     0:00 /usr/sbin/sshd -D\n"
            "  721 ?        Ss     2:17 nginx: master process /usr/sbin/nginx\n"
            "  722 ?        S      0:48 nginx: worker process\n"
            "  810 ?        Ss     1:52 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)\n"
            "  811 ?        S      0:31 php-fpm: pool www\n"
            "  934 ?        Ssl    8:22 /usr/sbin/mysqld\n"
            " 1204 ?        Ss     0:00 /usr/sbin/cron -f\n"
            " 2871 pts/0    Ss     0:00 -bash\n"
            " 2903 pts/0    R+     0:00 ps aux"
        )

    def _cmd_netstat(self, _args: List[str], _line: str) -> str:
        self._score_once("NETWORK_ENUM")
        self._latency("medium")
        lan = self.identity.get("fake_lan_ip", "10.0.1.50")
        return (
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN\n"
            f"tcp        0      0 {lan}:22          {ADMIN_IP}:51442          ESTABLISHED\n"
            "tcp6       0      0 :::443                  :::*                    LISTEN"
        )

    def _cmd_ifconfig(self, _args: List[str], _line: str) -> str:
        self._score_once("NETWORK_ENUM")
        lan = self.identity.get("fake_lan_ip", "10.0.1.50")
        mac = self.identity.get("fake_mac", "02:42:ac:11:00:02")
        return (
            f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            f"        inet {lan}  netmask 255.255.255.0  broadcast 10.0.1.255\n"
            f"        ether {mac}  txqueuelen 1000  (Ethernet)\n"
            f"        RX packets 8842193  bytes 4821094412 (4.8 GB)\n"
            f"        TX packets 6120847  bytes 1204918822 (1.2 GB)\n\n"
            f"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            f"        inet 127.0.0.1  netmask 255.0.0.0\n"
            f"        loop  txqueuelen 1000  (Local Loopback)"
        )

    def _cmd_ip(self, args: List[str], line: str) -> str:
        if args and args[0].startswith("a"):
            return self._cmd_ifconfig(args, line)
        if args and args[0].startswith("r"):
            self._score_once("NETWORK_ENUM")
            return ("default via 10.0.1.1 dev eth0 proto static\n"
                    "10.0.1.0/24 dev eth0 proto kernel scope link src "
                    + self.identity.get("fake_lan_ip", "10.0.1.50"))
        return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"

    def _cmd_arp(self, _args: List[str], _line: str) -> str:
        self._score_once("NETWORK_ENUM")
        return ("Address                  HWtype  HWaddress           Flags Mask            Iface\n"
                "10.0.1.1                 ether   00:1b:21:3c:4d:5e   C                     eth0\n"
                f"{ADMIN_IP.ljust(24)} ether   00:50:56:9a:11:c2   C                     eth0\n"
                "10.0.1.23                ether   00:50:56:9a:44:71   C                     eth0")

    def _cmd_nmap(self, args: List[str], line: str) -> str:
        """Scan the scanner: whatever they aim at, the report comes back on them.

        Nothing is actually scanned. The honeypot has no egress by design, and
        scanning back would be both a real port scan launched at a third party
        -- unlawful in most places, and their address is often a victim's box
        rather than theirs -- and an instant tell, since the packets would come
        from this host. So the port list is fabricated deterministically from
        their address, the way every other answer in this shell is.

        The `Host script results` block is not fabricated. It is what this
        honeypot has actually recorded about them, which is the part that lands.
        """
        self._score_once("NETWORK_ENUM", payload=line[:200])
        self._latency("slow")

        if not SCANBACK:
            return ("Starting Nmap 7.80 ( https://nmap.org ) at "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC\n"
                    "Failed to resolve \"" + (args[0] if args else "") + "\".\n"
                    "WARNING: No targets were specified, so 0 hosts scanned.\n"
                    "Nmap done: 0 IP addresses (0 hosts up) scanned in 0.29 seconds")

        # Imported here rather than at module scope: this is the only place in
        # the fake shell that needs live state, and a top-level import would
        # couple two modules that are otherwise independent.
        from . import identity as _identity

        try:
            live = _identity.get_or_create_identity(self.ip)
        except Exception:
            live = self.identity

        rng = random.Random(zlib.crc32(self.ip.encode()))
        open_ports = sorted(rng.sample(SCANBACK_PORTS, rng.randint(2, 4)))
        filtered = 1000 - len(open_ports)

        rows = "\n".join(
            f"{str(port) + '/tcp':<10}open  {name}" for port, name in open_ports
        )

        touched = live.get("services_touched") or []
        creds = len(live.get("credentials") or [])
        events = len(live.get("session_history") or [])
        first_seen = str(live.get("first_seen") or "")[:19]

        return (
            "Starting Nmap 7.80 ( https://nmap.org ) at "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"Nmap scan report for {self.ip}\n"
            f"Host is up (0.00{rng.randint(11, 89)}s latency).\n"
            f"Not shown: {filtered} filtered ports\n"
            "PORT      STATE SERVICE\n"
            f"{rows}\n\n"
            "Host script results:\n"
            "| clients-observed:\n"
            f"|   address: {self.ip}\n"
            f"|   first seen: {first_seen}\n"
            f"|   sessions logged: {events}\n"
            f"|   services probed: {', '.join(touched) if touched else 'ssh'}\n"
            f"|   credentials offered: {creds}\n"
            f"|_  threat score: {float(live.get('score') or 0):.0f}\n\n"
            f"Nmap done: 1 IP address (1 host up) scanned in "
            f"{rng.randint(9, 26)}.{rng.randint(10, 99)} seconds"
        )

    def _cmd_docker(self, args: List[str], _line: str) -> str:
        self._score_once("DOCKER_K8S_ENUM", payload=" ".join(args)[:120])
        self._latency("medium")
        return "bash: docker: command not found"

    def _cmd_kubectl(self, args: List[str], _line: str) -> str:
        self._score_once("DOCKER_K8S_ENUM", payload=" ".join(args)[:120])
        return "bash: kubectl: command not found"

    def _cmd_history(self, _args: List[str], _line: str) -> str:
        recent = self.history[-20:]
        width = len(str(len(self.history)))
        start = len(self.history) - len(recent) + 1
        return "\n".join(f"{i + start:>{width + 3}}  {cmd}" for i, cmd in enumerate(recent))

    def _cmd_crontab(self, args: List[str], _line: str) -> str:
        if "-l" in args or "-e" in args:
            return CRONTAB
        return "crontab: usage error: file name must be specified for replace"

    def _cmd_systemctl(self, args: List[str], _line: str) -> str:
        self._latency("medium")
        if not args or args[0] != "status":
            return ""
        unit = args[1] if len(args) > 1 else "nginx"
        return self._systemctl_status(unit)

    def _cmd_journalctl(self, _args: List[str], _line: str) -> str:
        self._latency("medium")
        stamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        host = self.hostname
        return "\n".join([
            f"{stamp} {host} nginx[721]: {ADMIN_IP} - - \"GET /wp-admin/ HTTP/1.1\" 200 4821",
            f"{stamp} {host} php-fpm[810]: [pool www] child 811 said into stderr: \"NOTICE: PHP message: cache warm\"",
            f"{stamp} {host} mysqld[934]: 2024-01-15T03:12:44.201Z 0 [Note] InnoDB: Buffer pool(s) load completed",
            f"{stamp} {host} systemd[1]: Started Daily apt download activities.",
            f"{stamp} {host} cron[1204]: (root) CMD (/usr/bin/php /opt/monitoring/check.php > /dev/null 2>&1)",
            f"{stamp} {host} sshd[689]: Accepted publickey for root from {ADMIN_IP} port 51442 ssh2",
        ])

    def _cmd_lsof(self, _args: List[str], _line: str) -> str:
        self._score_once("NETWORK_ENUM")
        self._latency("medium")
        lan = self.identity.get("fake_lan_ip", "10.0.1.50")
        return (
            "COMMAND   PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "sshd      689     root    3u  IPv4  16482      0t0  TCP *:ssh (LISTEN)\n"
            "nginx     721     root    6u  IPv4  17033      0t0  TCP *:http (LISTEN)\n"
            "mysqld    934    mysql   32u  IPv4  17944      0t0  TCP localhost:mysql (LISTEN)\n"
            f"sshd     2870     root    3u  IPv4  22841      0t0  TCP {lan}:ssh->{ADMIN_IP}:51442 (ESTABLISHED)"
        )

    def _cmd_strace(self, args: List[str], _line: str) -> str:
        self._sleep(3.0)
        target = args[0] if args else "program"
        return (
            f"execve(\"/usr/bin/{target}\", [\"{target}\"], 0x7ffd1a2b3c40 /* 23 vars */) = -1 ENOENT"
            " (No such file or directory)\n"
            f"strace: Can't stat '{target}': No such file or directory\n"
            "+++ exited with 1 +++"
        )

    def _cmd_gcc(self, args: List[str], _line: str) -> str:
        self._sleep(2.0)
        target = next((a for a in args if not a.startswith("-")), "a.c")
        return f"gcc: error: {target}: No such file or directory\ngcc: fatal error: no input files\ncompilation terminated."

    def _cmd_make(self, _args: List[str], _line: str) -> str:
        self._sleep(2.0)
        return "make: *** No targets specified and no makefile found.  Stop."

    def _cmd_git(self, args: List[str], _line: str) -> str:
        if args and args[0] == "clone":
            self._sleep(3.0)
            url = args[1] if len(args) > 1 else "https://github.com/example/repo.git"
            host = re.sub(r"^\w+://", "", url).split("/")[0].split("@")[-1]
            return f"Cloning into '{url.rstrip('/').split('/')[-1].replace('.git', '')}'...\nfatal: unable to connect to {host}:\n{host}: Connection refused"
        return "usage: git [--version] [--help] [-C <path>] <command> [<args>]"

    def _cmd_apt(self, args: List[str], _line: str) -> str:
        self._latency("medium")
        if args and args[0] in ("install", "update", "upgrade", "remove"):
            return ("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), "
                    "are you root?")
        return "apt 2.4.11 (amd64)"

    def _cmd_pip(self, args: List[str], _line: str) -> str:
        self._latency("medium")
        if args and args[0] == "install":
            pkg = args[1] if len(args) > 1 else "package"
            return (f"Defaulting to user installation because normal site-packages is not writeable\n"
                    f"Collecting {pkg}\n"
                    f"  Downloading {pkg}-2.1.0-py3-none-any.whl (48 kB)\n"
                    f"Installing collected packages: {pkg}\n"
                    f"Successfully installed {pkg}-2.1.0")
        return "pip 22.0.2 from /usr/lib/python3/dist-packages/pip (python 3.10)"

    def _cmd_wget(self, args: List[str], _line: str) -> str:
        self._sleep(3.0)
        url = next((a for a in args if not a.startswith("-")), "http://example.com")
        host = re.sub(r"^\w+://", "", url).split("/")[0]
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return (f"--{stamp}--  {url}\n"
                f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
                f"wget: unable to resolve host address '{host}'")

    def _cmd_curl(self, args: List[str], _line: str) -> str:
        self._sleep(3.0)
        url = next((a for a in args if not a.startswith("-")), "http://example.com")
        host = re.sub(r"^\w+://", "", url).split("/")[0]
        return f"curl: (6) Could not resolve host: {host}"

    def _cmd_chmod(self, _args: List[str], _line: str) -> str:
        return ""

    def _cmd_base64(self, args: List[str], line: str) -> str:
        if "-d" in args or "--decode" in args:
            self._score_always("REVERSE_SHELL", payload=line[:200])
            return "bash: /dev/tcp/127.0.0.1/4444: Connection timed out"
        return ""

    def _cmd_df(self, _args: List[str], _line: str) -> str:
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                "udev            1.9G     0  1.9G   0% /dev\n"
                "tmpfs           394M  1.1M  393M   1% /run\n"
                "/dev/vda1        79G   31G   45G  41% /\n"
                "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
                "/dev/vda15      105M  6.1M   99M   6% /boot/efi")

    def _cmd_free(self, _args: List[str], _line: str) -> str:
        return ("               total        used        free      shared  buff/cache   available\n"
                "Mem:            3936        1482         241          38        2212        2158\n"
                "Swap:           2047         118        1929")

    def _cmd_uptime(self, _args: List[str], _line: str) -> str:
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return f" {now} up 47 days,  3:19,  1 user,  load average: 0.28, 0.34, 0.31"

    def _cmd_w(self, _args: List[str], _line: str) -> str:
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return (f" {now} up 47 days,  3:19,  1 user,  load average: 0.28, 0.34, 0.31\n"
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"root     pts/0    {ADMIN_IP.ljust(17)}08:14    0.00s  0.04s  0.00s -bash")

    def _cmd_who(self, _args: List[str], _line: str) -> str:
        return f"root     pts/0        2024-01-15 08:14 ({ADMIN_IP})"

    def _cmd_env(self, _args: List[str], _line: str) -> str:
        return "\n".join([
            "SHELL=/bin/bash",
            f"PWD={self.cwd}",
            f"LOGNAME={self.username}",
            f"HOME=/{'root' if self.username == 'root' else 'home/' + self.username}",
            "LANG=en_US.UTF-8",
            "TERM=xterm-256color",
            f"USER={self.username}",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            f"DB_PASSWORD={persona.get('db_password')}",
        ])

    def _cmd_echo(self, args: List[str], _line: str) -> str:
        return " ".join(args)

    def _cmd_find(self, args: List[str], _line: str) -> str:
        self._score_once("RECON_LS")
        self._latency("slow")
        base = next((a for a in args if not a.startswith("-")), self.cwd)
        # Must agree with the tree in identity.py: an attacker who runs both
        # `find` and `ls` and gets different filenames has found the seam.
        year, month = (persona.pool("upload_path") + ["2024", "01"])[:2]
        documents = persona.pool("document_pool") or ["strategic-plan-2024.pdf"]
        uploads = "\n".join(
            f"{base}/wp-content/uploads/{year}/{month}/{name}"
            for name in documents
        )
        return (f"{base}/wp-config.php\n{base}/index.php\n"
                f"{uploads}\n"
                "find: '/root': Permission denied")

    def _cmd_grep(self, _args: List[str], _line: str) -> str:
        self._latency("medium")
        return ""

    def _cmd_su(self, args: List[str], _line: str) -> str:
        self._sleep(2.0)
        target = args[0] if args and not args[0].startswith("-") else "root"
        self._score_always("CREDENTIAL_ATTEMPT", payload=f"su {target}")
        return "su: Authentication failure"

    def _cmd_sudo(self, args: List[str], _line: str) -> str:
        self._sleep(1.5)
        self._score_always("CREDENTIAL_ATTEMPT", payload=" ".join(args)[:120])
        return (f"[sudo] password for {self.username}: \n"
                f"sudo: 1 incorrect password attempt")

    def _cmd_passwd(self, _args: List[str], _line: str) -> str:
        self._sleep(1.5)
        return "passwd: Authentication token manipulation error\npasswd: password unchanged"

    def _cmd_mkdir(self, args: List[str], _line: str) -> str:
        # `mkdir -p ~/.ssh` must not only stay silent but actually create the
        # directory, or the `echo >> ~/.ssh/authorized_keys` that follows lands
        # somewhere a later `ls` disagrees with.
        for target in (a for a in args if not a.startswith("-")):
            resolved = self._resolve(target)
            parts = [p for p in resolved.strip("/").split("/") if p]
            node = self.identity.get("fake_filesystem")
            if not isinstance(node, dict) or not parts:
                continue
            for part in parts:
                children = node.setdefault("children", {})
                child = children.get(part)
                if child is None or child.get("type") != "dir":
                    child = {"type": "dir", "mode": "drwx------", "children": {}}
                    children[part] = child
                node = child
        return ""

    def _cmd_rm(self, args: List[str], _line: str) -> str:
        target = next((a for a in args if not a.startswith("-")), "")
        return f"rm: cannot remove '{target}': Permission denied" if target else ""

    def _cmd_touch(self, _args: List[str], _line: str) -> str:
        return ""

    def _cmd_exit(self, _args: List[str], _line: str) -> str:
        self.exit_requested = True
        return "logout"

    def _cmd_noop(self, _args: List[str], _line: str) -> str:
        return ""

    # --------------------------------------------------------------- content

    def _reverse_shell(self, line: str) -> str:
        self._score_always("REVERSE_SHELL", payload=line[:300])
        self._sleep(3.0)
        match = HOST_PORT_RE.search(line)
        host = match.group(1) if match else "127.0.0.1"
        port = match.group(2) if match else "4444"
        return f"bash: connect to host {host} port {port}: Connection timed out"

    def _passwd_file(self) -> str:
        lines = [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
            "mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false",
        ]
        for user in self.identity.get("fake_users") or []:
            if user["username"] in ("root", "www-data"):
                continue
            lines.append(f"{user['username']}:x:{user['uid']}:{user['gid']}:"
                         f"{user['username'].title()},,,:{user['home']}:{user['shell']}")
        return "\n".join(lines)

    def _shadow_file(self) -> str:
        lines = ["root:$6$rounds=656000$YQ8kP2mN$3vK9dL2xQwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcdefgh:19700:0:99999:7:::"]
        for user in self.identity.get("fake_users") or []:
            if user["username"] == "root":
                continue
            if user["username"] == "www-data":
                lines.append("www-data:*:19700:0:99999:7:::")
                continue
            lines.append(f"{user['username']}:$6$rounds=656000$Xm4pQ8vL$8fH3kD9sN2mVbC7xZ1qW"
                         f"4rT6yU0iOpAsDfGhJkL5nMzXcVb:19700:0:99999:7:::")
        return "\n".join(lines)

    def _wp_config(self) -> str:
        # The credentials here are honeytokens: nothing accepts them, so a
        # login attempt with one anywhere is proof of where it was stolen from.
        # That only holds while they are unique to this deployment.
        return (
            "<?php\n"
            f"define( 'DB_NAME', '{persona.get('db_name')}' );\n"
            f"define( 'DB_USER', '{persona.get('db_user')}' );\n"
            f"define( 'DB_PASSWORD', '{persona.get('db_password')}' );\n"
            "define( 'DB_HOST', '127.0.0.1:3306' );\n"
            "define( 'DB_CHARSET', 'utf8mb4' );\n"
            f"define( 'AUTH_KEY',  '{persona.get('honeytoken_key')}' );\n"
            "$table_prefix = 'wp_';\n"
            "define( 'WP_DEBUG', false );\n"
            "require_once ABSPATH . 'wp-settings.php';"
        )

    def _os_release(self) -> str:
        os_name = self.identity.get("fake_os", "Ubuntu 22.04.3 LTS")
        return (f'PRETTY_NAME="{os_name}"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                f'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n'
                f'HOME_URL="https://www.ubuntu.com/"')

    def _systemctl_status(self, unit: str) -> str:
        units = {
            "nginx": ("nginx.service - A high performance web server and a reverse proxy server",
                      721, "2.1M", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
            "apache2": ("apache2.service - The Apache HTTP Server", 0, "", ""),
            "mysql": ("mysql.service - MySQL Community Server", 934, "412.8M", "/usr/sbin/mysqld"),
        }
        key = unit.replace(".service", "")
        if key == "apache2":
            return ("Unit apache2.service could not be found.")
        if key not in units:
            return f"Unit {unit}.service could not be found."
        desc, pid, mem, exe = units[key]
        return (
            f"● {desc}\n"
            f"     Loaded: loaded (/lib/systemd/system/{key}.service; enabled; vendor preset: enabled)\n"
            f"     Active: active (running) since Mon 2023-11-27 04:51:12 UTC; 1 month 18 days ago\n"
            f"   Main PID: {pid} ({key})\n"
            f"      Tasks: 3 (limit: 4632)\n"
            f"     Memory: {mem}\n"
            f"        CPU: 14min 22.418s\n"
            f"     CGroup: /system.slice/{key}.service\n"
            f"             └─{pid} {exe}\n\n"
            f"Warning: some journal files were not opened due to insufficient permissions."
        )

    _HANDLERS: Dict[str, Callable[["FakeShell", List[str], str], str]] = {}


def _cmd_chattr(self, args, _line):
    """Silence, which is what success looks like.

    `chattr -ia .ssh` is the first step of the standard SSH persistence chain:
    clear the immutable flag so authorized_keys can be rewritten. Returning
    "command not found" both breaks the illusion and ends the intrusion before
    the interesting part -- the key they were about to install.
    """
    self._score_once("PERSISTENCE_ATTEMPT", payload=" ".join(args)[:200])
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        return "Usage: chattr [-RVf] [-+=aAcCdDeijPsStTu] [-v version] files..."
    return ""


def _cmd_lsattr(self, args, _line):
    targets = [a for a in args if not a.startswith("-")] or ["."]
    return "\n".join(f"--------------e----- {name}" for name in targets)


def _cmd_nproc(self, _args, _line):
    return str(self._cpu_count())


def _cmd_lscpu(self, _args, _line):
    self._score_once("PROCESS_ENUM")
    cores = self._cpu_count()
    return (
        "Architecture:            x86_64\n"
        "  CPU op-mode(s):        32-bit, 64-bit\n"
        "  Address sizes:         46 bits physical, 48 bits virtual\n"
        "  Byte Order:            Little Endian\n"
        f"CPU(s):                  {cores}\n"
        f"  On-line CPU(s) list:   0-{cores - 1}\n"
        "Vendor ID:               GenuineIntel\n"
        "  Model name:            Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        "    CPU family:          6\n"
        "    Model:               79\n"
        f"    Thread(s) per core:  1\n"
        f"    Core(s) per socket:  {cores}\n"
        "    Socket(s):           1\n"
        "    Stepping:            1\n"
        "    BogoMIPS:            4800.02\n"
        "Virtualization features:\n"
        "  Hypervisor vendor:     KVM\n"
        "  Virtualization type:   full"
    )


def _cmd_lspci(self, _args, _line):
    # A KVM guest genuinely has no VGA controller worth reporting; returning
    # nothing is both accurate and what the probe expects on a VPS.
    return ""


def _cmd_last(self, _args, _line):
    self._score_once("RECON_LS")
    host = self.identity.get("fake_lan_ip", "10.0.1.50")
    return (
        f"{self.username:<9}pts/0        {host}      Mon Jan 15 08:14   still logged in\n"
        f"root     pts/0        {host}      Sun Jan 14 22:03 - 23:41  (01:38)\n"
        f"root     tty1                      Sun Jan 14 19:12 - 19:44  (00:32)\n"
        "\nwtmp begins Mon Dec  4 06:22:11 2023"
    )


def _cmd_printf(self, args, _line):
    if not args:
        return ""
    # Enough of printf(1) to satisfy the format strings probes actually use.
    text = args[0].replace("\\n", "\n").replace("\\t", "\t")
    if "%s" in text:
        for value in args[1:]:
            text = text.replace("%s", value, 1)
    return text


FakeShell._cmd_chattr = _cmd_chattr
FakeShell._cmd_lsattr = _cmd_lsattr
FakeShell._cmd_nproc = _cmd_nproc
FakeShell._cmd_lscpu = _cmd_lscpu
FakeShell._cmd_lspci = _cmd_lspci
FakeShell._cmd_last = _cmd_last
FakeShell._cmd_printf = _cmd_printf


def _cpu_count(self) -> int:
    """Stable per-IP, so repeat visits see the same machine."""
    return 2 + (zlib.crc32(self.ip.encode()) % 3) * 2


FakeShell._cpu_count = _cpu_count


FakeShell._HANDLERS = {
    "chattr": FakeShell._cmd_chattr,
    "lsattr": FakeShell._cmd_lsattr,
    "nproc": FakeShell._cmd_nproc,
    "lscpu": FakeShell._cmd_lscpu,
    "lspci": FakeShell._cmd_lspci,
    "last": FakeShell._cmd_last, "lastlog": FakeShell._cmd_last,
    "printf": FakeShell._cmd_printf,
    "ls": FakeShell._cmd_ls, "dir": FakeShell._cmd_ls,
    "cd": FakeShell._cmd_cd,
    "pwd": FakeShell._cmd_pwd,
    "cat": FakeShell._cmd_cat, "less": FakeShell._cmd_cat,
    "more": FakeShell._cmd_cat, "head": FakeShell._cmd_cat, "tail": FakeShell._cmd_cat,
    "id": FakeShell._cmd_id,
    "whoami": FakeShell._cmd_whoami,
    "uname": FakeShell._cmd_uname,
    "ps": FakeShell._cmd_ps,
    "top": FakeShell._cmd_ps, "htop": FakeShell._cmd_ps,
    "netstat": FakeShell._cmd_netstat, "ss": FakeShell._cmd_netstat,
    "ifconfig": FakeShell._cmd_ifconfig,
    "ip": FakeShell._cmd_ip,
    "arp": FakeShell._cmd_arp,
    "bash": FakeShell._cmd_sh, "sh": FakeShell._cmd_sh,
    "dash": FakeShell._cmd_sh, "ash": FakeShell._cmd_sh, "zsh": FakeShell._cmd_sh,
    "nmap": FakeShell._cmd_nmap, "masscan": FakeShell._cmd_nmap,
    "zmap": FakeShell._cmd_nmap, "rustscan": FakeShell._cmd_nmap,
    "docker": FakeShell._cmd_docker,
    "kubectl": FakeShell._cmd_kubectl,
    "history": FakeShell._cmd_history,
    "crontab": FakeShell._cmd_crontab,
    "systemctl": FakeShell._cmd_systemctl, "service": FakeShell._cmd_systemctl,
    "journalctl": FakeShell._cmd_journalctl,
    "lsof": FakeShell._cmd_lsof,
    "strace": FakeShell._cmd_strace, "ltrace": FakeShell._cmd_strace,
    "gcc": FakeShell._cmd_gcc, "cc": FakeShell._cmd_gcc, "g++": FakeShell._cmd_gcc,
    "make": FakeShell._cmd_make,
    "git": FakeShell._cmd_git,
    "apt": FakeShell._cmd_apt, "apt-get": FakeShell._cmd_apt,
    "yum": FakeShell._cmd_apt, "dnf": FakeShell._cmd_apt,
    "pip": FakeShell._cmd_pip, "pip3": FakeShell._cmd_pip,
    "wget": FakeShell._cmd_wget,
    "curl": FakeShell._cmd_curl,
    "chmod": FakeShell._cmd_chmod, "chown": FakeShell._cmd_chmod,
    "base64": FakeShell._cmd_base64,
    "df": FakeShell._cmd_df,
    "free": FakeShell._cmd_free,
    "uptime": FakeShell._cmd_uptime,
    "w": FakeShell._cmd_w,
    "who": FakeShell._cmd_who,
    "env": FakeShell._cmd_env, "printenv": FakeShell._cmd_env, "set": FakeShell._cmd_env,
    "echo": FakeShell._cmd_echo,
    "find": FakeShell._cmd_find, "locate": FakeShell._cmd_find,
    "grep": FakeShell._cmd_grep, "egrep": FakeShell._cmd_grep,
    "su": FakeShell._cmd_su,
    "sudo": FakeShell._cmd_sudo,
    "passwd": FakeShell._cmd_passwd,
    "mkdir": FakeShell._cmd_mkdir,
    "rm": FakeShell._cmd_rm, "rmdir": FakeShell._cmd_rm,
    "touch": FakeShell._cmd_touch,
    "exit": FakeShell._cmd_exit, "logout": FakeShell._cmd_exit, "quit": FakeShell._cmd_exit,
    "clear": FakeShell._cmd_noop, "export": FakeShell._cmd_noop,
    "cp": FakeShell._cmd_noop, "mv": FakeShell._cmd_noop,
    # All silent on success, and all steps in the drop-and-run chain. chmod
    # missing was its own tell: `chmod +x payload` returned command not found
    # on a box that had just accepted the write.
    "chmod": FakeShell._cmd_noop, "chown": FakeShell._cmd_noop,
    "unset": FakeShell._cmd_noop, "alias": FakeShell._cmd_noop,
    "true": FakeShell._cmd_noop, ":": FakeShell._cmd_noop,
    "sync": FakeShell._cmd_noop, "sleep": FakeShell._cmd_noop,
}
