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

from shared import alerting, identity, scoring  # noqa: E402
from shared.fakeshell import FakeShell  # noqa: E402

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "2222"))
SERVICE = "ssh"
HOST_KEY_PATH = os.getenv("SSH_HOST_KEY", "/app/state/ssh_host_key")
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

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

    def __init__(self, ip: str):
        self.ip = ip
        self.username = "root"
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.username = username or "root"
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
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username or "root"
        identity.score_named_event(
            self.ip, "CREDENTIAL_ATTEMPT",
            payload=f"publickey {key.get_name()} {key.get_fingerprint().hex()}"[:200],
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
    try:
        sock.settimeout(TARPIT_BYTE_DELAY + 5)
        for char in SSH_BANNER:
            if time.time() > deadline:
                break
            sock.sendall(char.encode())
            time.sleep(TARPIT_BYTE_DELAY)
        while time.time() < deadline:
            junk = "".join(random.choice(string.ascii_letters + string.digits)
                           for _ in range(random.randint(8, 40)))
            sock.sendall((junk + "\r\n").encode())
            time.sleep(random.uniform(5.0, 12.0))
    except (OSError, socket.timeout):
        pass
    finally:
        held = time.time() - started
        alerting.alert_event(
            ip=ip, event_type="TARPIT_HELD", service=SERVICE,
            reason=f"SSH tarpit held connection {held:.0f}s",
            tarpit_active=True, held_seconds=round(held, 1),
        )
        try:
            sock.close()
        except OSError:
            pass


def interactive_session(channel, ip: str, ident: dict, username: str) -> None:
    """Line-oriented fake bash over the SSH channel."""
    shell = FakeShell(ip, ident, score=identity.score_named_event,
                      service=SERVICE, username=username)
    recorder = alerting.SessionRecorder(ip, SERVICE, title=f"ssh {username}@{shell.hostname}")

    motd = (
        f"Welcome to {ident.get('fake_os', 'Ubuntu 22.04.3 LTS')} "
        f"(GNU/Linux {ident.get('fake_kernel', '5.15.0-86-generic')} x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        "Last login: Mon Jan 15 08:14:02 2024 from 10.0.1.9\r\n"
    )
    channel.sendall(motd.encode())
    recorder.write_output(motd)

    buffer = ""
    channel.settimeout(SESSION_IDLE_TIMEOUT)
    try:
        while not shell.exit_requested:
            prompt = shell.prompt()
            channel.sendall(prompt.encode())
            recorder.write_output(prompt)

            line = None
            while line is None:
                data = channel.recv(4096)
                if not data:
                    return
                text = data.decode("utf-8", "replace")
                recorder.write_input(text)
                for char in text:
                    if char in ("\r", "\n"):
                        channel.sendall(b"\r\n")
                        recorder.write_output("\r\n")
                        line = buffer
                        buffer = ""
                        break
                    if char in ("\x7f", "\b"):
                        if buffer:
                            buffer = buffer[:-1]
                            channel.sendall(b"\b \b")
                        continue
                    if char == "\x03":
                        channel.sendall(b"^C\r\n")
                        line = ""
                        buffer = ""
                        break
                    if char == "\x04":
                        shell.exit_requested = True
                        line = "exit"
                        break
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
    finally:
        recorder.close()


def handle_client(sock: socket.socket, addr) -> None:
    ip = addr[0]
    try:
        if identity.is_banned(ip):
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

        server = HoneypotServer(ip)
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
            identity.activate_tarpit(ip, f"{label} on SSH", SERVICE)

        channel = transport.accept(30)
        if channel is None:
            transport.close()
            return

        server.event.wait(20)
        command = getattr(server, "exec_command", None)
        if command:
            shell = FakeShell(ip, ident, score=identity.score_named_event,
                              service=SERVICE, username=server.username)
            output = shell.run(command)
            if output:
                channel.sendall((output + "\n").encode())
            channel.send_exit_status(0)
        else:
            interactive_session(channel, ip, ident, server.username)

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
