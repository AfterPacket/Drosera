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

    # --- the busybox presence check --------------------------------------
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
