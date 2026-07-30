#!/usr/bin/env python3
"""Fake SSH daemon with an endlessh-style tarpit, fake shell, and SFTP sink.

Binds an unprivileged port inside the container; the host maps 22 to it, so the
process never needs root or CAP_NET_BIND_SERVICE.

Zero-trust: no command is ever executed, no file is ever written from attacker
input, and SFTP payloads are counted and discarded.
"""

import os
import random
import socket
import string
import sys
import threading
import time

import paramiko

sys.path.insert(0, "/app")

from shared import alerting, identity, loot, persona, rickroll, scoring, tarpit  # noqa: E402
from shared.fakeshell import FakeShell  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "2222"))
SERVICE = "ssh"
HOST_KEY_PATH = os.getenv("SSH_HOST_KEY", "/app/state/ssh_host_key")
# The very first bytes any scanner sees, and so the cheapest fingerprint there
# is. Comes from the deployment's persona rather than the published source.
SSH_BANNER = persona.get("ssh_banner")

MAX_CONNECTIONS = int(os.getenv("SSH_MAX_CONNECTIONS", "200"))
TARPIT_MAX_SECONDS = int(os.getenv("SSH_TARPIT_MAX_SECONDS", "1800"))
TARPIT_BYTE_DELAY = float(os.getenv("SSH_TARPIT_BYTE_DELAY", "1.0"))
AUTH_DELAY_RANGE = (1.0, 3.0)
SESSION_IDLE_TIMEOUT = int(os.getenv("SSH_SESSION_TIMEOUT", "600"))

_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

CLIENT_TOOLS = [
    ("libssh", "TOOL_HYDRA", "Hydra"),
    ("medusa", "TOOL_HYDRA", "Medusa"),
    ("ncrack", "TOOL_OTHER", "Ncrack"),
    ("paramiko", "TOOL_OTHER", "paramiko"),
    ("asyncssh", "TOOL_OTHER", "AsyncSSH"),
    ("go", "TOOL_OTHER", "Go SSH client"),
    ("russh", "TOOL_OTHER", "russh"),
    ("metasploit", "TOOL_METASPLOIT", "Metasploit"),
]


def detect_client_tool(banner: str) -> tuple:
    low = (banner or "").lower()
    for needle, event, label in CLIENT_TOOLS:
        if needle in low:
            return event, label
    return "", ""


def load_host_key() -> paramiko.RSAKey:
    directory = os.path.dirname(HOST_KEY_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    if os.path.exists(HOST_KEY_PATH):
        try:
            return paramiko.RSAKey(filename=HOST_KEY_PATH)
        except Exception:
            pass
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


class HoneypotServer(paramiko.ServerInterface):
    """Accepts every credential, but scores and records each attempt."""

    def __init__(self, ip: str, hostname: str = "srv-01"):
        self.ip = ip
        self.hostname = hostname
        self.username = "root"
        self.event = threading.Event()
        self.recorder = None

    def rec(self):
        """The session recorder, created on first authentication attempt.

        Lazily, so a bare TCP probe or a handshake that never authenticates does
        not leave an empty .cast behind. From the first credential onward the
        recording covers the whole connection -- login attempts included, and
        continuing into the shell if they open one -- rather than starting only
        when a channel appears. Most bots never open a channel at all, and their
        credential attempts are the entire capture.
        """
        if self.recorder is None:
            self.recorder = alerting.SessionRecorder(
                self.ip, SERVICE, title=f"ssh from {self.ip}")
            self.recorder.write_output(SSH_BANNER + "\r\n")
        return self.recorder

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.username = username or "root"

        # Written before the artificial delay so the recording reflects the
        # attempt even if the client gives up mid-authentication. The password
        # is shown in the clear where a real client would mask it -- this is
        # our evidence, not their terminal, and the credential is the point.
        recorder = self.rec()
        recorder.write_output(f"login as: {self.username}\r\n")
        recorder.write_output(
            f"{self.username}@{self.hostname}'s password: {password or ''}\r\n")

        time.sleep(random.uniform(*AUTH_DELAY_RANGE))

        identity.record_credential(self.ip, username or "", password or "", SERVICE)
        identity.score_named_event(
            self.ip, "CREDENTIAL_ATTEMPT",
            payload=f"{username}:{password}"[:200], service=SERVICE,
        )
        if identity.detect_spray(self.ip):
            identity.score_named_event(
                self.ip, "CREDENTIAL_SPRAY",
                payload=f"{username}:{password}"[:200], service=SERVICE,
            )
            identity.activate_tarpit(self.ip, "SSH credential spray", SERVICE)

        if identity.is_banned(self.ip):
            recorder.write_output("Permission denied, please try again.\r\n")
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username or "root"
        fingerprint = key.get_fingerprint().hex()
        recorder = self.rec()
        recorder.write_output(f"login as: {self.username}\r\n")
        recorder.write_output(
            f"Offered public key: {key.get_name()} {fingerprint}\r\n"
            f"{self.username}@{self.hostname}: Permission denied (publickey).\r\n")
        identity.score_named_event(
            self.ip, "CREDENTIAL_ATTEMPT",
            payload=f"publickey {key.get_name()} {fingerprint}"[:200],
            service=SERVICE,
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth,
                                  pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        """Non-interactive `ssh host <cmd>` -- answer once and close."""
        self.exec_command = command.decode("utf-8", "replace")
        self.event.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        result = super().check_channel_subsystem_request(channel, name)
        self.event.set()
        return result


class QuarantineHandle(paramiko.SFTPHandle):
    """Accepts an SFTP upload into memory, then quarantines it.

    Buffered rather than streamed to disk: the file only becomes real once it
    is content-addressed by hash, so an attacker-controlled path never touches
    the filesystem even transiently. Capped at the same size shared/loot.py
    would truncate to, so the buffer cannot itself become the disk attack.
    """

    def __init__(self, ip: str, path: str):
        super().__init__(0)
        self.ip = ip
        self.path = path
        self._chunks = []
        self._size = 0

    def write(self, offset, data):
        if self._size < loot.MAX_FILE_BYTES:
            self._chunks.append(data)
            self._size += len(data)
        return paramiko.SFTP_OK

    def read(self, offset, length):
        # Upload sink only. Reading back would let them verify their own drop,
        # and there is nothing to gain by helping with that.
        return paramiko.SFTP_PERMISSION_DENIED

    def close(self):
        try:
            digest = loot.capture(
                b"".join(self._chunks), ip=self.ip, service="sftp",
                origin="sftp-put", filename=self.path,
            )
            if digest:
                identity.score_named_event(
                    self.ip, "FILE_UPLOAD", service="sftp",
                    payload=f"quarantined {digest[:16]} ({self._size}B) {self.path}"[:200],
                )
                alerting.alert_event(
                    self.ip, "LOOT_CAPTURED", service="sftp",
                    payload=f"{digest} {self._size}B via sftp {self.path}"[:200],
                )
        except Exception:
            pass
        finally:
            self._chunks = []
        return paramiko.SFTP_OK


class SFTPSink(paramiko.SFTPServerInterface):
    """Logs every SFTP path and discards all content."""

    def __init__(self, server, *largs, **kwargs):
        self.ip = getattr(server, "ip", "0.0.0.0")
        super().__init__(server, *largs, **kwargs)

    def _log(self, action: str, path: str) -> None:
        identity.score_named_event(
            self.ip, "RECON_LS", payload=f"sftp {action} {path}"[:200], service="sftp",
        )

    def list_folder(self, path):
        self._log("list", path)
        return paramiko.SFTP_OK

    def stat(self, path):
        self._log("stat", path)
        return paramiko.SFTP_NO_SUCH_FILE

    def lstat(self, path):
        self._log("lstat", path)
        return paramiko.SFTP_NO_SUCH_FILE

    def open(self, path, flags, attr):
        self._log("open", path)
        identity.score_named_event(
            self.ip, "FILE_UPLOAD", payload=f"sftp put {path}"[:200], service="sftp",
        )
        # Denying the write logs that an upload was attempted and throws the
        # payload away. Accepting it into quarantine is the whole point: the
        # binary is the most valuable thing an attacker ever gives you, and
        # refusing it also tells them the box is not real.
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
            return QuarantineHandle(self.ip, path)
        return paramiko.SFTP_PERMISSION_DENIED

    def remove(self, path):
        self._log("remove", path)
        return paramiko.SFTP_PERMISSION_DENIED

    def mkdir(self, path, attr):
        self._log("mkdir", path)
        return paramiko.SFTP_PERMISSION_DENIED


def run_tarpit(sock: socket.socket, ip: str) -> None:
    """endlessh: trickle junk pre-banner lines so the client blocks on read.

    RFC 4253 lets a server send arbitrary lines before its version string, so a
    conforming client keeps waiting. Capped so our own socket table stays bounded.
    """
    identity.score_named_event(ip, "TARPIT_ENGAGED", payload="ssh tarpit", service=SERVICE)
    deadline = time.time() + TARPIT_MAX_SECONDS
    held = 0.0
    started = time.time()

    # Recorded like any other connection. This path had no recorder at all,
    # which meant the addresses held longest were the ones with the least
    # evidence against them: once an IP crosses the threshold every subsequent
    # SSH connection arrives here, so its recordings stopped exactly when it
    # became interesting. The transcript is thin by nature -- nobody reaches a
    # shell through a tarpit -- but "held 412s, client gave up" is a fact worth
    # having in the evidence bundle.
    recorder = alerting.SessionRecorder(ip, SERVICE, title=f"ssh tarpit from {ip}")
    recorder.write_output(f"SSH tarpit engaged for {ip}\r\n")
    # Registered for the duration so the dashboard can show this connection
    # being drained while it is happening, not only after it ends.
    hold_key = tarpit.begin_hold(ip, SERVICE, TARPIT_MAX_SECONDS)
    # Time of the last write the peer actually accepted. Held time is measured
    # to here, not to whenever the failure surfaced: a client that disconnects
    # during one of the sleeps below is not discovered until the next send
    # raises, and counting that gap would credit the tarpit with up to twelve
    # seconds per connection that cost the attacker nothing. Over thousands of
    # holds that is hours of imaginary time.
    last_ok = time.time()
    try:
        sock.settimeout(TARPIT_BYTE_DELAY + 5)
        for char in SSH_BANNER:
            if time.time() > deadline:
                break
            sock.sendall(char.encode())
            last_ok = time.time()
            time.sleep(TARPIT_BYTE_DELAY)
        while time.time() < deadline:
            junk = "".join(random.choice(string.ascii_letters + string.digits)
                           for _ in range(random.randint(8, 40)))
            sock.sendall((junk + "\r\n").encode())
            last_ok = time.time()
            recorder.write_output(junk + "\r\n")
            time.sleep(random.uniform(5.0, 12.0))
    except (OSError, socket.timeout):
        pass
    finally:
        tarpit.end_hold(hold_key)
        held = max(last_ok - started, 0.0)
        recorder.write_output(
            f"\r\nclient gave up after {held:.0f}s\r\n")
        recorder.close()
        alerting.alert_event(
            ip=ip, event_type="TARPIT_HELD", service=SERVICE,
            reason=f"SSH tarpit held connection {held:.0f}s",
            tarpit_active=True, held_seconds=round(held, 1),
        )
        try:
            sock.close()
        except OSError:
            pass


def interactive_session(channel, ip: str, ident: dict, username: str,
                        recorder) -> None:
    """Line-oriented fake bash over the SSH channel.

    The recorder is passed in rather than created here: it was opened at the
    first authentication attempt, so one .cast covers login and shell as a
    single session, the way the connection actually happened.
    """
    shell = FakeShell(ip, ident, score=identity.score_named_event,
                      service=SERVICE, username=username)

    # The last-login line is per-deployment: a fixed timestamp and source IP
    # published in this repository would identify every host still using them.
    motd = (
        f"Welcome to {ident.get('fake_os', 'Ubuntu 22.04.3 LTS')} "
        f"(GNU/Linux {ident.get('fake_kernel', '5.15.0-86-generic')} x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        f"Last login: {persona.get('last_login_at')} "
        f"from {persona.get('last_login_from')}\r\n"
    )
    channel.sendall(motd.encode())
    recorder.write_output(motd)

    buffer = ""       # the line being typed
    # Input received but not yet consumed. Without this, everything after the
    # first newline in a packet was dropped on the floor: a human types one
    # character at a time so it never showed, but automation pipes an entire
    # script in one write. A worm sending `uname -a\ncat /etc/passwd\nwget ...`
    # got its first command answered and the rest silently discarded, then
    # disconnected when its next expectation went unmet.
    pending = ""
    channel.settimeout(SESSION_IDLE_TIMEOUT)
    try:
        while not shell.exit_requested:
            prompt = shell.prompt()
            channel.sendall(prompt.encode())
            recorder.write_output(prompt)

            line = None
            while line is None:
                if not pending:
                    data = channel.recv(4096)
                    if not data:
                        return
                    pending = data.decode("utf-8", "replace")
                    recorder.write_input(pending)

                char, pending = pending[0], pending[1:]

                if char in ("\r", "\n"):
                    # Swallow the \n of a CRLF pair so a pasted script does not
                    # produce a blank command and a spurious prompt per line.
                    if char == "\r" and pending.startswith("\n"):
                        pending = pending[1:]
                    channel.sendall(b"\r\n")
                    recorder.write_output("\r\n")
                    line = buffer
                    buffer = ""
                    continue
                if char in ("\x7f", "\b"):
                    if buffer:
                        buffer = buffer[:-1]
                        channel.sendall(b"\b \b")
                    continue
                if char == "\x03":
                    channel.sendall(b"^C\r\n")
                    line = ""
                    buffer = ""
                    continue
                if char == "\x04":
                    shell.exit_requested = True
                    line = "exit"
                    continue
                buffer += char
                channel.sendall(char.encode())

            if line is None:
                continue
            output = shell.run(line)
            if output:
                payload = output.replace("\n", "\r\n") + "\r\n"
                channel.sendall(payload.encode())
                recorder.write_output(payload)
    except (OSError, socket.timeout, EOFError):
        pass


def handle_client(sock: socket.socket, addr) -> None:
    ip = addr[0]
    server = None
    try:
        if identity.is_banned(ip):
            # Pre-banner, which RFC 4253 §4.2 explicitly allows: a server may
            # send any number of other lines before its version string, and a
            # conforming client skips them. It is the same slot run_tarpit()
            # drips junk into, so nothing new is being asked of the client.
            #
            # Dripped, so the ban path is a tarpit rather than a parting shot:
            # a banned scanner's last act here is to spend two minutes
            # collecting a picture. Registered as a hold like any other, so
            # the time shows up on the dashboard and in attacker-minutes.
            art = rickroll.banner()
            if art:
                sock.settimeout(rickroll.DRIP_SECONDS + 30)
                hold_key = tarpit.begin_hold(ip, SERVICE, rickroll.DRIP_SECONDS)
                try:
                    held = tarpit.drip_sync(
                        sock, art, time.time() + rickroll.DRIP_SECONDS,
                        byte_delay=rickroll.drip_delay(art))
                finally:
                    tarpit.end_hold(hold_key)
                tarpit.log_hold(ip, SERVICE, held, reason="ssh rickroll (banned)")
            sock.close()
            return

        ident = identity.get_or_create_identity(ip)
        identity.score_named_event(ip, "CONNECTION_ANY", service=SERVICE)

        if identity.is_tarpitted(ip):
            run_tarpit(sock, ip)
            return

        transport = paramiko.Transport(sock)
        transport.local_version = SSH_BANNER
        transport.add_server_key(load_host_key())
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, SFTPSink)

        server = HoneypotServer(ip, ident.get("fake_hostname") or "srv-01")
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, OSError):
            transport.close()
            return

        event, label = detect_client_tool(transport.remote_version or "")
        if event:
            identity.score_named_event(
                ip, event, payload=transport.remote_version, tool=label, service=SERVICE,
            )
            # Deliberately NOT tarpitted on detection.
            #
            # Recognising Hydra and then stonewalling it throws away the only
            # thing it was going to give us: the wordlist. A brute-forcer that
            # is allowed to run captures hundreds of credential pairs, which is
            # real intelligence about what is circulating. One that is tarpitted
            # after its first attempt captures one pair and a lot of noise.
            #
            # The score still climbs on every attempt, so a persistent tool
            # reaches the tarpit and ban thresholds on its own -- just later,
            # and with the evidence already collected.

        channel = transport.accept(30)
        if channel is None:
            # Authenticated and left without opening a channel -- a credential
            # validator. The recording still holds the login attempt, which is
            # the whole of what they did.
            transport.close()
            return

        server.event.wait(20)
        command = getattr(server, "exec_command", None)
        if command:
            # `ssh host '<cmd>'`. This is the most common bot pattern by far,
            # and it used to be the one path that ran a command without
            # recording it -- so the dropper and persistence one-liners, which
            # are the payloads actually worth watching, produced an event log
            # entry and no footage. Non-interactive is not uninteresting.
            shell = FakeShell(ip, ident, score=identity.score_named_event,
                              service=SERVICE, username=server.username)
            recorder = server.rec()
            recorder.write_output(shell.prompt() + command + "\r\n")
            output = shell.run(command)
            if output:
                channel.sendall((output + "\n").encode())
                recorder.write_output(output.replace("\n", "\r\n") + "\r\n")
            channel.send_exit_status(0)
        else:
            interactive_session(channel, ip, ident, server.username, server.rec())

        try:
            channel.close()
        except OSError:
            pass
        transport.close()
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
    finally:
        # Closed here, not in the branches: the recording spans the whole
        # connection, so it ends when the attacker's session does -- however
        # they leave, and whichever path they took.
        if server is not None and server.recorder is not None:
            server.recorder.close()
        _slots.release()


def main() -> None:
    load_host_key()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(128)
    print(f"[*] fake sshd listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)

    while True:
        try:
            client, addr = server_sock.accept()
        except OSError:
            continue
        # Shed load rather than exhausting memory when a scanner floods us.
        if not _slots.acquire(blocking=False):
            try:
                client.close()
            except OSError:
                pass
            continue
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
