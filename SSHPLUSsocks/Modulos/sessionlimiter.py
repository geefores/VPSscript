#!/usr/bin/env python3
"""SSHPLUS unified per-user session limiter for SSH, Dropbear and OpenVPN."""
import csv
import io
import json
import os
import pwd
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

DB = Path(os.environ.get('SSHPLUS_LIMIT_DB', '/root/usuarios.db'))
INTERVAL = 6
OPENVPN_STATUS = [Path('/etc/openvpn/openvpn-status.log'), Path('/etc/openvpn/server/openvpn-status.log'), Path('/var/log/openvpn/status.log')]
OPENVPN_MANAGEMENT = ('127.0.0.1', 7505)
DRY_RUN = os.environ.get('DRY_RUN', '0') == '1'
ONCE = os.environ.get('ONCE', '0') == '1'


def run(args, timeout=5):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ''


def load_limits():
    limits = {}
    try:
        for line in DB.read_text(errors='replace').splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] and parts[1].isdigit():
                limits[parts[0]] = max(1, int(parts[1]))
    except OSError:
        pass
    return limits


def active_dropbear_sessions():
    """Map active Dropbear child PIDs to usernames using journald auth records."""
    records = {}
    raw = run(['journalctl', '-u', 'dropbear', '--since', '24 hours ago', '-o', 'json', '--no-pager'], timeout=8)
    for line in raw.splitlines():
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        msg = str(entry.get('MESSAGE', ''))
        match = re.search(r"(?:Password|Pubkey|Public key) auth succeeded for '([^']+)'", msg, re.I)
        pid = entry.get('_PID')
        if match and str(pid or '').isdigit():
            records[int(pid)] = match.group(1)
    sockets = run(['ss', '-Htnp', 'state', 'established'], timeout=5)
    active = {}
    for line in sockets.splitlines():
        if 'dropbear' not in line:
            continue
        for p in re.findall(r'pid=(\d+)', line):
            pid = int(p)
            user = records.get(pid)
            if user:
                active[pid] = user
    return active


def active_sshd_sessions():
    """Return session child PIDs for OpenSSH; exclude listeners and priv monitors."""
    result = {}
    try:
        lines = subprocess.check_output(['ps', '-eo', 'pid=,uid=,comm=,args='], text=True, timeout=5).splitlines()
    except (OSError, subprocess.SubprocessError):
        return result
    for line in lines:
        parts = line.strip().split(None, 3)
        if len(parts) < 4 or parts[2] != 'sshd':
            continue
        try:
            pid, uid = int(parts[0]), int(parts[1])
            user = pwd.getpwuid(uid).pw_name
        except (ValueError, KeyError):
            continue
        args = parts[3]
        if args.startswith('sshd: ') and '@' in args and not args.endswith('[listener]') and '[priv]' not in args:
            result[pid] = user
    return result


def active_openvpn_sessions():
    """Return OpenVPN sessions mapped to a configured username when possible.

    OpenVPN status v2 distinguishes Common Name from authenticated Username.
    Prefer Username from the header; only use Common Name as a fallback when it
    exactly matches an account in usuarios.db, avoiding cross-user miscounting.
    """
    sessions = {}
    limits = load_limits()
    status = next((p for p in OPENVPN_STATUS if p.is_file()), None)
    if not status:
        return sessions
    try:
        lines = status.read_text(errors='replace').splitlines()
    except OSError:
        return sessions

    header = None
    for line in lines:
        if line.startswith('HEADER,CLIENT_LIST,'):
            try:
                header = next(csv.reader([line]))[2:]
            except (csv.Error, IndexError):
                header = None
            break

    for line in lines:
        if not (line.startswith('CLIENT_LIST,') or line.startswith('CLIENT_LIST\t')):
            continue
        try:
            fields = next(csv.reader([line])) if line.startswith('CLIENT_LIST,') else [x.strip() for x in line.split('\t')]
        except csv.Error:
            continue
        if len(fields) < 2:
            continue
        common_name = fields[1].strip()
        user = ''
        client_id = ''
        if header:
            # fields[0] is CLIENT_LIST; header[0] maps to fields[1].
            try:
                username_index = header.index('Username') + 1
                if username_index < len(fields):
                    user = fields[username_index].strip()
            except ValueError:
                pass
            try:
                client_id_index = header.index('Client ID') + 1
                if client_id_index < len(fields):
                    client_id = fields[client_id_index].strip()
            except ValueError:
                pass
        # Legacy status formats may not include authenticated Username.
        if not user and common_name in limits:
            user = common_name
        if user in limits:
            sessions.setdefault(user, []).append(client_id)
    return sessions


def kill_openvpn_client(client_id, username):
    """Disconnect a single client when possible; fallback to exact CN on legacy status."""
    try:
        with socket.create_connection(OPENVPN_MANAGEMENT, timeout=2) as sock:
            sock.settimeout(1)
            try:
                sock.recv(4096)
            except OSError:
                pass
            command = f'client-kill {client_id}\n' if client_id.isdigit() else f'kill {username}\n'
            sock.sendall(command.encode())
            try:
                sock.recv(4096)
            except OSError:
                pass
            return True
    except OSError:
        return False


def terminate_pid(pid, expected_user, method):
    if DRY_RUN:
        print(f'DRY_RUN: would terminate {method} session PID {pid} for {expected_user}', flush=True)
        return True
    try:
        if method == 'dropbear':
            cmd = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            if '/usr/sbin/dropbear' not in cmd or ' -2 ' not in f' {cmd} ':
                return False
        elif method == 'sshd':
            cmd = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            if 'sshd:' not in cmd or expected_user not in cmd or '[priv]' in cmd or '[listener]' in cmd:
                return False
        os.kill(pid, signal.SIGTERM)
        return True
    except (OSError, ProcessLookupError):
        return False


def check_once():
    limits = load_limits()
    if not limits:
        print('Limiter: no valid users/limits in /root/usuarios.db', flush=True)
        return
    drop = active_dropbear_sessions()
    sshd = active_sshd_sessions()
    ovpn = active_openvpn_sessions()
    sessions = {u: [] for u in limits}
    for pid, user in sshd.items():
        if user in sessions:
            sessions[user].append(('sshd', pid, ''))
    for pid, user in drop.items():
        if user in sessions:
            sessions[user].append(('dropbear', pid, ''))
    for user, ids in ovpn.items():
        if user in sessions:
            for client_id in ids:
                sessions[user].append(('openvpn', 0, client_id))

    for user, limit in limits.items():
        active = sessions.get(user, [])
        excess = len(active) - limit
        print(f'{user}: {len(active)}/{limit} active session(s)', flush=True)
        if excess <= 0:
            continue
        # Terminate one exact session at a time; preserve at least the configured limit.
        for method, pid, client_id in active:
            if excess <= 0:
                break
            if method in ('dropbear', 'sshd'):
                if terminate_pid(pid, user, method):
                    excess -= 1
            elif method == 'openvpn':
                if DRY_RUN:
                    print(f'DRY_RUN: would disconnect OpenVPN client {client_id or user}', flush=True)
                    excess -= 1
                elif kill_openvpn_client(client_id, user):
                    excess -= 1
        if excess > 0:
            print(f'WARNING: {user} remains over limit; could not safely terminate {excess} session(s)', flush=True)


def main():
    while True:
        check_once()
        if ONCE:
            return
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
