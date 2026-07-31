#!/usr/bin/env python3
"""Check the handshake a Mirai-family loader performs before it infects.

The loader logs in, sends a hex-escaped `echo -e`, and reads the result back to
decide whether it is talking to a real shell. If the answer is wrong it hangs
up in about a second -- before the busybox probe, before the loader URL, before
the payload. Everything the IOC extractor and the quarantine fetcher exist for
is downstream of these few exchanges, so they are worth asserting.
"""

import os
import pathlib
import sys
import tempfile
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("REDIS_HOST", "127.0.0.1")
os.environ.setdefault("STORAGE_PATH", tempfile.mkdtemp(prefix="drosera-test-"))


def stub_redis_if_missing() -> None:
    """Let this run on a host without redis-py; see mysql-honey/test_sysvars.py."""
    try:
        import redis  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    class Unavailable(Exception):
        pass

    class Redis:
        def __init__(self, *args, **kwargs):
            raise Unavailable("redis-py not installed; stubbed for tests")

    module = types.ModuleType("redis")
    module.Redis = Redis
    module.RedisError = Unavailable
    module.ConnectionError = Unavailable
    module.TimeoutError = Unavailable
    module.exceptions = types.SimpleNamespace(
        RedisError=Unavailable, ConnectionError=Unavailable,
        TimeoutError=Unavailable)
    sys.modules["redis"] = module


stub_redis_if_missing()

from shared import identity  # noqa: E402
from shared.fakeshell import FakeShell, _expand_escapes  # noqa: E402

IP = "198.51.100.23"


def shell():
    ident = identity.get_or_create_identity(IP)
    return FakeShell(IP, ident, score=identity.score_named_event,
                     service="telnet", username="root")


def check(label, condition, detail=""):
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    return 0 if condition else 1


def main():
    bad = 0

    # --- the exact probe seen in the wild -------------------------------
    probe = r'echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"'
    out = shell().run(probe)
    bad += check("the auth_ok handshake decodes", out == "auth_ok", repr(out))

    # A flag echoed back is what gave the old bug away.
    bad += check("no flag leaks into the output", "-e" not in out, repr(out))

    # --- flag handling --------------------------------------------------
    bad += check("-en is treated as combined flags",
                 shell().run(r'echo -en "\x68\x69"') == "hi")
    bad += check("-E leaves escapes literal",
                 shell().run(r'echo -E "\x68\x69"') == r"\x68\x69")
    bad += check("no -e means no expansion, as in bash",
                 shell().run(r'echo "\x68\x69"') == r"\x68\x69")
    bad += check("an unknown flag prints rather than being eaten",
                 shell().run("echo -q hello") == "-q hello",
                 repr(shell().run("echo -q hello")))
    bad += check("plain echo still works",
                 shell().run("echo hello world") == "hello world")

    # --- escape coverage -------------------------------------------------
    bad += check("octal escapes decode", _expand_escapes(r"\0101\0102") == "AB",
                 repr(_expand_escapes(r"\0101\0102")))
    bad += check("single-digit hex decodes", _expand_escapes(r"\x9") == "\t",
                 repr(_expand_escapes(r"\x9")))
    bad += check("named escapes decode",
                 _expand_escapes(r"a\tb\nc") == "a\tb\nc")
    bad += check("a literal backslash survives",
                 _expand_escapes(r"a\\b") == r"a\b")
    bad += check("an unknown escape passes through untouched",
                 _expand_escapes(r"\q") == r"\q")
    bad += check("\\c truncates the rest",
                 _expand_escapes(r"keep\cdrop") == "keep")
    bad += check("a bare trailing backslash does not crash",
                 _expand_escapes("abc\\") == "abc\\")

    # --- command substitution, including nested parentheses ---------------
    #
    # The recon script every SSH dropper opens with is one long chain of these,
    # and its very first line nests a `( ... )` inside the `$( ... )`. A body
    # pattern of `[^()]*` stopped at the inner paren, so the substitution never
    # ran, the variable kept its own source text, and `echo "UNAME:$uname"`
    # replayed the attacker's script back at them.
    s = shell()
    out = s.run('v=$(echo hello); echo "V:$v"')
    bad += check("a simple substitution is executed", out.endswith("V:hello"), repr(out))

    s = shell()
    out = s.run('v=$(echo one || ( [ -f /nope ] && echo two )); echo "V:$v"')
    bad += check("a nested parenthesis does not break substitution",
                 "V:one" in out and "$(" not in out, repr(out))

    s = shell()
    out = s.run('v=$(uname -s 2>/dev/null || ( [ -f /proc/version ] && echo x )); echo "U:$v"')
    bad += check("the real recon opener resolves",
                 "U:" in out and "$(" not in out and "||" not in out, repr(out))

    bad += check("backticks still work",
                 shell().run('v=`echo hi`; echo "V:$v"').endswith("V:hi"))
    bad += check("an unterminated substitution does not hang",
                 isinstance(shell().run('echo $(echo broken'), str))

    # --- shell grammar is not a command ----------------------------------
    for fragment in ["case", "esac", "in", "done", "fi", "*)", "*xxxxxx*)"]:
        out = shell().run(fragment)
        bad += check(f"{fragment!r} is not reported as a missing command",
                     "command not found" not in out, repr(out))

    # --- their own file can be removed ------------------------------------
    s = shell()
    s.run('printf "#!/bin/sh\\necho ok\\n" > filter')
    out = s.run("rm -rf filter")
    bad += check("a file they created can be deleted",
                 "Permission denied" not in out, repr(out))
    out = shell().run("rm -rf /etc/passwd")
    bad += check("a file they did not create still cannot be",
                 "Permission denied" in out, repr(out))

    # --- the busybox presence check --------------------------------------
    #
    # A telnet loader runs the shell-escape sequence then `/bin/busybox` with
    # no arguments at all. That reported "command not found", which on an
    # embedded target means the binary is absent and ends the conversation.
    out = shell().run("/bin/busybox")
    bad += check("bare busybox prints its banner",
                 "BusyBox v" in out and "multi-call binary" in out, repr(out[:80]))
    bad += check("bare busybox is not a missing command",
                 "command not found" not in out and "applet not found" not in out)
    out = shell().run("busybox --list")
    bad += check("busybox --list is an option, not an applet name",
                 "applet not found" not in out and "wget" in out, repr(out[:80]))

    # ping has to agree with wget, or the pair contradict each other.
    out = shell().run("ping -c 3 8.8.8.8")
    bad += check("ping to an address reports loss, not a missing command",
                 "100% packet loss" in out, repr(out))
    out = shell().run("ping -c 3 example.com")
    bad += check("ping to a name fails to resolve, as wget does",
                 "Temporary failure in name resolution" in out, repr(out))

    out = shell().run("enable")
    bad += check("enable is a builtin, not a missing command",
                 "command not found" not in out and "enable echo" in out,
                 repr(out[:80]))

    out = shell().run("/bin/busybox MIRAI")
    bad += check("an unknown busybox applet reports 'applet not found'",
                 out == "MIRAI: applet not found", repr(out))
    out = shell().run("/bin/busybox ECHO")
    bad += check("busybox applet names stay case-sensitive, as real busybox is",
                 out == "ECHO: applet not found", repr(out))

    # Real applets must still dispatch through busybox.
    out = shell().run(r'/bin/busybox echo -e "\x6f\x6b"')
    bad += check("a real applet still runs via busybox", out == "ok", repr(out))

    # A command that is genuinely absent is still a shell error, not an applet.
    out = shell().run("definitelynotreal")
    bad += check("a plain missing command is still 'command not found'",
                 out == "bash: definitelynotreal: command not found", repr(out))

    print()
    print("all checks passed" if not bad else f"{bad} check(s) failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
