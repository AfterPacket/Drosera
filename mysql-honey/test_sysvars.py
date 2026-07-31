#!/usr/bin/env python3
"""Check that a client's connection-setup probes get usable answers.

Every MySQL client asks for @@max_allowed_packet and friends before it sends
anything worth reading, and it configures itself from the reply. These assert
that the reply is well-formed *and* that its contents are sane -- a perfectly
framed result set saying max_allowed_packet is 1 byte still ends the session.
"""

import asyncio
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mysql-honey"))
os.environ.setdefault("REDIS_HOST", "127.0.0.1")

import fake_mysqld as m  # noqa: E402


def parse_result_set(blob):
    """Walk the packets back apart. Returns (columns, rows).

    Verifies the framing as it goes: sequence numbers must run consecutively
    from 1, and every packet's declared length must match what follows.
    """
    offset, sequence = 0, 1
    packets = []
    while offset < len(blob):
        length = int.from_bytes(blob[offset:offset + 3], "little")
        seq = blob[offset + 3]
        assert seq == sequence, f"sequence jumped: expected {sequence}, got {seq}"
        body = blob[offset + 4:offset + 4 + length]
        assert len(body) == length, "packet truncated"
        packets.append(body)
        offset += 4 + length
        sequence += 1
    assert offset == len(blob), "trailing bytes after last packet"

    assert packets, "empty response"
    if packets[0][:1] == b"\x00":
        return None, None  # OK packet
    if packets[0][:1] == b"\xff":
        raise AssertionError(f"server returned an error: {packets[0][3:]!r}")

    count = packets[0][0]
    columns = []
    for body in packets[1:1 + count]:
        # def, schema, table, org_table, name, org_name -- name is the 5th.
        pos, fields = 0, []
        for _ in range(6):
            size = body[pos]
            fields.append(body[pos + 1:pos + 1 + size].decode())
            pos += 1 + size
        columns.append(fields[4])

    body_packets = packets[1 + count:]
    assert body_packets[0][:1] == b"\xfe", "missing EOF after column defs"
    assert body_packets[-1][:1] == b"\xfe", "missing EOF after rows"

    rows = []
    for body in body_packets[1:-1]:
        pos, cells = 0, []
        while pos < len(body):
            if body[pos] == 0xFB:
                cells.append(None)
                pos += 1
                continue
            size = body[pos]
            assert size < 251, "test only handles short strings"
            cells.append(body[pos + 1:pos + 1 + size].decode())
            pos += 1 + size
        rows.append(cells)
    return columns, rows


def ask(sql):
    return parse_result_set(asyncio.run(m.answer_query("198.51.100.7", sql)))


def check(label, condition, detail=""):
    mark = "ok  " if condition else "FAIL"
    print(f"{mark} {label}" + (f"  -- {detail}" if detail and not condition else ""))
    return condition


def main():
    failures = 0

    # The query that was ending every session.
    columns, rows = ask("SELECT @@max_allowed_packet")
    failures += not check("@@max_allowed_packet names its column",
                          columns == ["@@max_allowed_packet"], f"got {columns}")
    value = int(rows[0][0])
    failures += not check("@@max_allowed_packet is a usable size",
                          value >= 1024, f"got {value}")
    failures += not check("@@max_allowed_packet matches what we accept",
                          value == m.MAX_PACKET,
                          f"advertised {value}, enforced {m.MAX_PACKET}")

    # The first thing the mysql CLI sends, before anything else.
    columns, rows = ask("select @@version_comment limit 1")
    failures += not check("@@version_comment answered",
                          columns == ["@@version_comment"] and rows[0][0],
                          f"got {columns} {rows}")

    # Connectors ask for several at once and match them up positionally.
    columns, rows = ask("SELECT @@sql_mode, @@autocommit, @@lower_case_table_names")
    failures += not check("multi-variable select keeps order and arity",
                          columns == ["@@sql_mode", "@@autocommit",
                                      "@@lower_case_table_names"]
                          and len(rows) == 1 and len(rows[0]) == 3,
                          f"got {columns} {rows}")

    # session./global. qualifiers are common and must not become unknowns.
    columns, rows = ask("SELECT @@session.wait_timeout")
    failures += not check("qualified variable resolves",
                          columns == ["@@session.wait_timeout"]
                          and int(rows[0][0]) > 0, f"got {columns} {rows}")

    # The other spelling of the same probe.
    columns, rows = ask("SHOW VARIABLES LIKE 'max_allowed_packet'")
    failures += not check("SHOW VARIABLES honours LIKE",
                          rows == [["max_allowed_packet", str(m.MAX_PACKET)]],
                          f"got {rows}")

    columns, rows = ask("SHOW VARIABLES LIKE 'character\\_set\\_%'")
    failures += not check("LIKE wildcards match a family",
                          len(rows) >= 4
                          and all(r[0].startswith("character_set") for r in rows),
                          f"got {rows}")

    columns, rows = ask("SHOW VARIABLES")
    failures += not check("bare SHOW VARIABLES still lists everything",
                          len(rows) == len(m.SYSVARS), f"got {len(rows)} rows")

    # An unknown variable is answered, not errored -- an error tells a
    # fingerprinter more than the answer does.
    columns, rows = ask("SELECT @@wsrep_cluster_size")
    failures += not check("unknown variable answered rather than refused",
                          columns == ["@@wsrep_cluster_size"] and rows,
                          f"got {columns} {rows}")

    # Regression: the branches that used to run before this one must still win.
    columns, rows = ask("SELECT table_name FROM information_schema.tables")
    failures += not check("information_schema still takes precedence",
                          columns == ["table_schema", "table_name"],
                          f"got {columns}")

    columns, rows = ask("SELECT version()")
    failures += not check("version() still answered",
                          columns == ["version()"] and rows[0][0] == m.SERVER_VERSION,
                          f"got {columns} {rows}")

    # A LIKE pattern is attacker-supplied; regex metacharacters are literal.
    columns, rows = ask("SHOW VARIABLES LIKE '.*'")
    failures += not check("regex metacharacters in LIKE are literal",
                          rows == [], f"got {rows}")

    print()
    print("all checks passed" if not failures else f"{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
