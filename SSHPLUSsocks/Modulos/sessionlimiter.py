#!/usr/bin/env python3
"""DEinternet shared per-user session limiter: Dropbear + OpenVPN.

GitHub target: SSHPLUSsocks/Modulos/sessionlimiter.py
OpenSSH is deliberately excluded. Limits are read from /root/usuarios.db.
Supports DRY_RUN=1 and ONCE=1. No service/config changes are performed.
"""
import csv
import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

DB = Path(os.environ.get("SSHPLUS_LIMIT_DB", "/root/usuarios.db"))
INTERVAL = 6
DROPBEAR_PORT = int(os.environ.get("DROPBEAR_PORT", "443"))
OPENVPN_STATUS_FILES = (
    Path("/etc/openvpn/openvpn-status.log"),
    Path("/etc/openvpn/server/openvpn-status.log"),
    Path("/var/log/openvpn/status.log"),
)
OPENVPN_MANAGEMENT_HOST = os.environ.get("OPENVPN_MANAGEMENT_HOST", "127.0.0.1")
OPENVPN_MANAGEMENT_PORT = int(os.environ.get("OPENVPN_MANAGEMENT_PORT", "7505"))
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
ONCE = os.environ.get("ONCE", "0") == "1"
USER_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.-]*\$?")


def run(args, timeout=8):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout,
                              check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def load_limits():
    limits = {}
    try:
        for line in DB.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            username = parts[0]
            if USER_RE.fullmatch(username):
                limits[username] = max(1, int(parts[1]))
    except OSError as exc:
        print(f"ERROR: cannot read limits database {DB}: {exc}", flush=True)
    return limits


def active_dropbear_sessions(limits):
    """Map established Dropbear child PIDs to users using auth messages.

    Dropbear embeds its child PID in the auth message as [PID]. journald's
    _PID field may instead identify the listener, so do not use _PID here.
    """
    sockets = run(["ss", "-Htnp", "state", "established",
                   f"( sport = :{DROPBEAR_PORT} )"])
    live_pids = set()
    for line in sockets.splitlines():
        if "dropbear" in line.lower():
            live_pids.update(int(pid) for pid in re.findall(r"pid=(\d+)", line))
    if not live_pids:
        return {}

    journal = run(["journalctl", "-u", "dropbear", "--since", "24 hours ago",
                   "-o", "cat", "--no-pager"], timeout=12)
    auth = re.compile(
        r"^\[(\d+)\].*(?:Password|Pubkey|Public key|Keyboard-interactive) "
        r"auth succeeded for '([^']+)'", re.IGNORECASE)
    records = {}
    for line in journal.splitlines():
        match = auth.search(line)
        if not match:
            continue
        pid, username = int(match.group(1)), match.group(2)
        if pid in live_pids and USER_RE.fullmatch(username):
            records[pid] = username

    sessions = {}
    for pid, username in records.items():
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(
                b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        # Only a Dropbear child session; never listener/master.
        if "dropbear" in cmdline.lower() and " -2 " in f" {cmdline} ":
            sessions[pid] = username
    return sessions


def active_openvpn_sessions(limits):
    """Return {username: [client_id, ...]} from OpenVPN status CSV."""
    status_file = next((p for p in OPENVPN_STATUS_FILES if p.is_file()), None)
    if status_file is None:
        print("INFO: OpenVPN status file not found; OpenVPN sessions not counted.",
              flush=True)
        return {}
    try:
        lines = status_file.read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"WARNING: cannot read OpenVPN status file: {exc}", flush=True)
        return {}

    header = None
    for line in lines:
        if line.startswith("HEADER,CLIENT_LIST,"):
            try:
                header = next(csv.reader([line]))[2:]
            except (csv.Error, IndexError):
                header = None
            break

    sessions = {}
    for line in lines:
        if not line.startswith("CLIENT_LIST,"):
            continue
        try:
            fields = next(csv.reader([line]))
        except csv.Error:
            continue
        if len(fields) < 2:
            continue
        common_name = fields[1].strip()
        username = ""
        client_id = ""
        if header:
            try:
                index = header.index("Username") + 1
                if index < len(fields):
                    username = fields[index].strip()
            except ValueError:
                pass
            try:
                index = header.index("Client ID") + 1
                if index < len(fields):
                    client_id = fields[index].strip()
            except ValueError:
                pass
        # Legacy status formats: fallback only on exact DB username match.
        if not username and common_name in limits:
            username = common_name
        if username in limits:
            sessions.setdefault(username, []).append(client_id)
    return sessions


def kill_openvpn_client(client_id, username):
    """Request disconnection through OpenVPN management interface."""
    try:
        with socket.create_connection(
                (OPENVPN_MANAGEMENT_HOST, OPENVPN_MANAGEMENT_PORT), timeout=3) as sock:
            sock.settimeout(2)
            try:
                sock.recv(4096)  # management greeting
            except OSError:
                pass
            command = (f"client-kill {client_id}\n" if client_id.isdigit()
                       else f"kill {username}\n")
            sock.sendall(command.encode())
            response = sock.recv(4096).decode(errors="replace").upper()
            return "SUCCESS" in response or "KILL" in response
    except OSError:
        return False


def terminate_dropbear(pid, expected_username):
    """Revalidate child identity, latest successful auth, and established socket."""
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(
            b"\0", b" ").decode(errors="replace")
        if "dropbear" not in cmdline.lower() or " -2 " not in f" {cmdline} ":
            return False

        # Do not signal a recycled PID or a process whose authenticated user
        # does not match the account currently being limited.
        journal = run(["journalctl", "-u", "dropbear", "--since", "24 hours ago",
                       "-o", "cat", "--no-pager"], timeout=12)
        auth = re.compile(
            rf"^\[{pid}\].*(?:Password|Pubkey|Public key|Keyboard-interactive) "
            r"auth succeeded for '([^']+)'", re.IGNORECASE)
        authenticated_user = None
        for line in journal.splitlines():
            match = auth.search(line)
            if match:
                authenticated_user = match.group(1)
        if authenticated_user != expected_username:
            print(f"WARNING: refusing to signal Dropbear PID {pid}: "
                  "authenticated username could not be confirmed.", flush=True)
            return False

        sockets = run(["ss", "-Htnp", "state", "established",
                       f"( sport = :{DROPBEAR_PORT} )"])
        pid_pattern = re.compile(rf"pid={pid}(?:,|\))")
        if not any("dropbear" in line.lower() and pid_pattern.search(line)
                   for line in sockets.splitlines()):
            return False
        os.kill(pid, signal.SIGTERM)
        run(["logger", "-t", "deinternet-session-limiter", "--",
             f"Disconnected Dropbear session user={expected_username} pid={pid} "
             "reason=per-user-session-limit"])
        return True
    except OSError:
        return False


def check_once():
    limits = load_limits()
    if not limits:
        print(f"ERROR: no valid limits in {DB}; no action taken.", flush=True)
        return
    combined = {username: [] for username in limits}
    for pid, username in active_dropbear_sessions(limits).items():
        if username in combined:
            combined[username].append(("dropbear", pid, ""))
    for username, client_ids in active_openvpn_sessions(limits).items():
        if username in combined:
            for client_id in client_ids:
                combined[username].append(("openvpn", 0, client_id))

    for username, limit in limits.items():
        active = combined[username]
        print(f"{username}: {len(active)}/{limit} active session(s) "
              "(Dropbear + OpenVPN; OpenSSH excluded)", flush=True)
        excess = len(active) - limit
        if excess <= 0:
            continue
        # Prefer newer Dropbear child PIDs first, then OpenVPN clients.
        active.sort(key=lambda item: (0 if item[0] == "dropbear" else 1, -item[1]))
        for method, pid, client_id in active:
            if excess <= 0:
                break
            if method == "dropbear":
                if DRY_RUN:
                    print(f"DRY_RUN: would disconnect Dropbear PID {pid} for {username}",
                          flush=True)
                    excess -= 1
                elif terminate_dropbear(pid, username):
                    print(f"Disconnected Dropbear session user={username} pid={pid}",
                          flush=True)
                    excess -= 1
            elif DRY_RUN:
                print(f"DRY_RUN: would disconnect OpenVPN client ID "
                      f"{client_id or '(unknown)'} for {username}", flush=True)
                excess -= 1
            elif kill_openvpn_client(client_id, username):
                print(f"Disconnected OpenVPN session user={username} "
                      f"client_id={client_id or '(unknown)'}", flush=True)
                excess -= 1
            else:
                print(f"WARNING: OpenVPN session for {username} exceeds limit, "
                      "but management did not confirm disconnection.", flush=True)
        if excess > 0:
            print(f"WARNING: {username} remains over limit by {excess}; "
                  "no unsafe process was terminated.", flush=True)


def main():
    while True:
        check_once()
        if ONCE:
            return
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
