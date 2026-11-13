#!/usr/bin/env python3
"""
VPN Gate Scanner TUI  -  tuned for Iran
=======================================
* Finds the daily VPN Gate mirror addresses automatically (kusrabyzarc/vpngate-daily-mirrors),
  pulls the server list from ALL mirrors in parallel and merges it.
* Runs several different tests per server (TCP/UDP OpenVPN handshake, TLS, real SSTP probe,
  IKE/L2TP probe, multi-round stability, optional real OpenVPN connect + speed test).
* Interactive menu: save .ovpn, connect, L2TP / SSTP details, favorites, history, export.

Usage:  python vpngate_tui.py  [--proxy socks5://127.0.0.1:1080] [--mirror http://1.2.3.4:5555/]
                               [--import file.csv] [--out ~/Downloads] [--no-flags]
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import datetime
import httpx
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, OptionList, ProgressBar, Static
from textual.widgets.option_list import Option

# ───────────────────────────── constants ─────────────────────────────

APP_DIR = Path(os.environ.get("VPNGATE_TUI_HOME", Path.home() / ".config" / "vpngate-tui"))
APP_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = APP_DIR / "cache.json"
PREFS_FILE = APP_DIR / "prefs.json"
EXTRA_MIRRORS_FILE = APP_DIR / "mirrors.txt"
DB_FILE = APP_DIR / "history.sqlite"

# Places that publish the daily mirror addresses (several, because some are filtered in Iran)
MIRROR_SOURCES = [
    "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/mirrors.json",
    "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@main/mirrors.json",
    "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/mirrors.csv",
    "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@main/mirrors.csv",
    "https://raw.githubusercontent.com/kusrabyzarc/vpngate-daily-mirrors/main/README.md",
    "https://cdn.jsdelivr.net/gh/kusrabyzarc/vpngate-daily-mirrors@main/README.md",
    "https://github.com/kusrabyzarc/vpngate-daily-mirrors",
]
OFFICIAL = ["https://www.vpngate.net/", "http://www.vpngate.net/"]  # blocked in Iran, last resort
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}/?")
UA = {"User-Agent": "Mozilla/5.0 (vpngate-tui)"}
SSTP_PATH = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"

USE_FLAGS = True
THEMES = ["textual-dark", "nord", "dracula", "tokyo-night", "gruvbox", "catppuccin-mocha", "monokai"]
FILTERS = ["All", "TCP", "UDP", "TCP/443", "SSTP ✔", "L2TP ✔", "OpenVPN ✔", "★ Favorites", "Blacklist"]
SORTS = {"1": "Score", "2": "Ping", "3": "Jitter", "4": "Speed", "5": "Country"}


@dataclass
class Config:
    proxy: Optional[str] = None
    mirrors: list = field(default_factory=list)
    import_path: Optional[str] = None
    out_dir: Path = field(default_factory=lambda: (Path.home() / "Downloads") if (Path.home() / "Downloads").exists() else Path.home() / "vpngate")
    samples: int = 5
    timeout: float = 4.0
    concurrency: int = 60
    rounds: int = 3
    interval: int = 30
    stability_top: int = 30
    deep_top: int = 10
    deep_timeout: int = 35


# ───────────────────────────── data model ─────────────────────────────

def flag(cc: str) -> str:
    cc = (cc or "").upper()
    if USE_FLAGS and len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)
    return f"[{cc}]" if cc else "🏳"


def _int(v, d=0):
    try:
        return int(float(v))
    except Exception:
        return d


@dataclass
class Server:
    ip: str
    host: str
    score: int
    ping: int
    speed: int
    country: str
    cc: str
    sessions: int
    uptime: int
    users: int
    traffic: int
    logtype: str
    operator: str
    message: str
    ovpn: str
    proto: str = "tcp"
    port: int = 443
    # test results
    samples: list = field(default_factory=list)
    ovpn_ok: Optional[bool] = None
    tls_ok: Optional[bool] = None
    tls_ms: Optional[float] = None
    sstp_ok: Optional[bool] = None
    l2tp_ok: Optional[bool] = None
    l2tp_ms: Optional[float] = None
    deep_ok: Optional[bool] = None
    deep_s: Optional[float] = None
    deep_mbps: Optional[float] = None
    deep_msg: str = ""
    round_avgs: list = field(default_factory=list)
    tested: bool = False
    final: float = 0.0

    @staticmethod
    def from_row(d: dict) -> Optional["Server"]:
        b64 = d.get("OpenVPN_ConfigData_Base64", "")
        if not d.get("IP"):
            return None
        if not b64 and not d.get("_sstp_only"):
            return None
        try:
            cfg = base64.b64decode(b64).decode("utf-8", "replace") if b64 else ""
        except Exception:
            return None
        proto, port = parse_ovpn(cfg) if cfg else ("tcp", 443)
        return Server(
            ip=d["IP"], host=d.get("HostName", ""), score=_int(d.get("Score")), ping=_int(d.get("Ping")),
            speed=_int(d.get("Speed")), country=d.get("CountryLong", "?"), cc=d.get("CountryShort", ""),
            sessions=_int(d.get("NumVpnSessions")), uptime=_int(d.get("Uptime")), users=_int(d.get("TotalUsers")),
            traffic=_int(d.get("TotalTraffic")), logtype=d.get("LogType", ""), operator=d.get("Operator", ""),
            message=d.get("Message", ""), ovpn=cfg, proto=proto, port=port,
        )

    # derived stats
    @property
    def ok_samples(self):
        return [x for x in self.samples if x is not None]

    @property
    def lat(self):
        v = self.ok_samples
        return statistics.fmean(v) if v else None

    @property
    def jitter(self):
        v = self.ok_samples
        return statistics.pstdev(v) if len(v) > 1 else 0.0

    @property
    def loss(self):
        return 100.0 * (1 - len(self.ok_samples) / len(self.samples)) if self.samples else 100.0

    @property
    def sstp_host(self):
        return f"{self.host}.opengw.net" if self.host else self.ip


def parse_ovpn(cfg: str):
    proto, port = "tcp", 443
    m = re.search(r"^\s*proto\s+(\S+)", cfg, re.M)
    if m:
        proto = "udp" if m.group(1).lower().startswith("udp") else "tcp"
    m = re.search(r"^\s*remote\s+\S+\s+(\d+)", cfg, re.M) or re.search(r"^\s*port\s+(\d+)", cfg, re.M)
    if m:
        port = int(m.group(1))
    return proto, port


def parse_api(text: str) -> list[dict]:
    lines = [l for l in text.replace("\r", "").split("\n") if l.strip() and not l.startswith("*")]
    if not lines:
        return []
    header = [h.strip().lstrip("#") for h in lines[0].split(",")]
    rows = []
    for row in csv.reader(lines[1:]):
        if len(row) >= len(header):
            rows.append(dict(zip(header, row)))
    return rows


# ───────────────────────────── scoring ─────────────────────────────

def compat_score(s: Server) -> float:
    """How likely this protocol/port combo survives Iranian DPI."""
    if s.proto == "tcp":
        base = 100 if s.port == 443 else 70
    else:
        base = 55 if s.port == 443 else 25 if s.port == 1194 else 40
    if not s.tested:
        return base
    best = base if s.ovpn_ok else 0
    if s.sstp_ok:
        best = max(best, 95)
    if s.l2tp_ok:
        best = max(best, 30)
    return best


def compute_score(s: Server) -> float:
    if s.tested:
        lat = s.lat
        lat_s = 0 if lat is None else max(0.0, 100 - max(0.0, lat - 80) * 0.25)
        jit_s = max(0.0, 100 - s.jitter * 2)
        loss_s = max(0.0, 100 - s.loss * 2.5)
    else:
        lat_s = jit_s = loss_s = 50
    spd_s = min(100.0, s.speed / 1e6 * 1.5)
    load_s = max(0.0, 100 - s.sessions / 3)
    final = 0.26 * lat_s + 0.10 * jit_s + 0.14 * loss_s + 0.10 * spd_s + 0.30 * compat_score(s) + 0.10 * load_s
    if s.tested and not (s.ovpn_ok or s.sstp_ok or s.l2tp_ok):
        final *= 0.1
    if len(s.round_avgs) > 1:
        vals = [v for v in s.round_avgs if v is not None]
        fails = len(s.round_avgs) - len(vals)
        if len(vals) > 1:
            final -= min(20, statistics.pstdev(vals) * 0.25)
        final -= 12 * fails
    if s.deep_ok is True:
        final += 8
        if s.deep_mbps:
            final += min(5, s.deep_mbps * 0.25)
    elif s.deep_ok is False:
        final *= 0.5
    s.final = max(0.0, min(100.0, final))
    return s.final


# ───────────────────────────── network probes ─────────────────────────────

async def _aclose(w):
    try:
        w.close()
        await asyncio.wait_for(w.wait_closed(), 1)
    except Exception:
        pass


class _UDP(asyncio.DatagramProtocol):
    def __init__(self):
        self.fut = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_result(None)


async def udp_exchange(ip, port, payload, timeout):
    loop = asyncio.get_running_loop()
    try:
        tr, pr = await loop.create_datagram_endpoint(_UDP, remote_addr=(ip, port))
    except OSError:
        return None, None
    t0 = time.perf_counter()
    try:
        tr.sendto(payload)
        data = await asyncio.wait_for(pr.fut, timeout)
        return data, (time.perf_counter() - t0) * 1000
    except asyncio.TimeoutError:
        return None, None
    finally:
        tr.close()


def ovpn_reset(sid: bytes, tcp: bool) -> bytes:
    """OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7). Server answers with opcode 8 containing our session id."""
    body = bytes([7 << 3]) + sid + b"\x00" + b"\x00\x00\x00\x00"
    return struct.pack("!H", len(body)) + body if tcp else body


async def ovpn_sample(s: Server, timeout: float):
    """One latency sample + OpenVPN handshake check. Returns (ms|None, handshake_ok)."""
    sid = os.urandom(8)
    if s.proto == "udp":
        data, rtt = await udp_exchange(s.ip, s.port, ovpn_reset(sid, False), timeout)
        ok = data is not None and sid in data
        return (rtt if ok else None), ok
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(s.ip, s.port), timeout)
    except Exception:
        return None, False
    ms = (time.perf_counter() - t0) * 1000
    ok = False
    try:
        w.write(ovpn_reset(sid, True))
        await w.drain()
        data = await asyncio.wait_for(r.read(64), timeout)
        ok = sid in data
    except Exception:
        pass
    await _aclose(w)
    return ms, ok


async def tls_probe(ip, port, sni, timeout, sstp=False):
    """TLS handshake (+ real SSTP_DUPLEX_POST probe). Returns (tls_ok, tls_ms, sstp_ok)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni), timeout)
    except Exception:
        return False, None, False
    ms = (time.perf_counter() - t0) * 1000
    sstp_ok = False
    if sstp:
        try:
            w.write((f"SSTP_DUPLEX_POST {SSTP_PATH} HTTP/1.1\r\nHost: {sni}\r\n"
                     "Content-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {00000000-0000-0000-0000-000000000000}\r\n\r\n").encode())
            await w.drain()
            data = await asyncio.wait_for(r.read(256), timeout)
            sstp_ok = data.startswith(b"HTTP/1.1 200")
        except Exception:
            pass
    await _aclose(w)
    return True, ms, sstp_ok


def ike_packet():
    icookie = os.urandom(8)

    def attr(t, v):
        return struct.pack("!HH", 0x8000 | t, v)

    def transform(num, last, enc):
        attrs = attr(1, enc) + (attr(14, 128) if enc == 7 else b"") + attr(2, 2) + attr(3, 1) + attr(4, 2) + attr(11, 1) + attr(12, 28800)
        return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), num, 1, 0) + attrs

    transforms = transform(1, False, 7) + transform(2, True, 5)  # AES128 / 3DES, SHA1, PSK, MODP1024
    prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 2) + transforms
    sa = struct.pack("!BBHII", 0, 0, 12 + len(prop), 1, 1) + prop
    hdr = icookie + bytes(8) + struct.pack("!BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa))
    return icookie, hdr + sa


async def l2tp_probe(ip, timeout):
    """IKEv1 main-mode initiation on UDP/500 - any answer with our cookie = L2TP/IPsec alive."""
    icookie, pkt = ike_packet()
    data, rtt = await udp_exchange(ip, 500, pkt, timeout)
    ok = bool(data) and data[:8] == icookie
    return ok, (rtt if ok else None)


async def quick_test_one(s: Server, cfg: Config):
    s.samples, hs_any = [], False
    for i in range(cfg.samples):
        ms, ok = await ovpn_sample(s, cfg.timeout)
        s.samples.append(ms)
        hs_any = hs_any or ok
        if i == 1 and not s.ok_samples:
            break  # dead - stop wasting time
        await asyncio.sleep(0.05)
    s.ovpn_ok = hs_any
    (s.tls_ok, s.tls_ms, s.sstp_ok), (s.l2tp_ok, s.l2tp_ms) = await asyncio.gather(
        tls_probe(s.ip, 443, s.sstp_host, cfg.timeout, sstp=True), l2tp_probe(s.ip, cfg.timeout)
    )
    s.round_avgs = [s.lat]
    s.tested = True
    compute_score(s)


async def stability_round(s: Server, cfg: Config):
    vals = []
    for _ in range(cfg.samples):
        ms, _ok = await ovpn_sample(s, cfg.timeout)
        if ms is not None:
            vals.append(ms)
        await asyncio.sleep(0.05)
    s.samples.extend(vals + [None] * (cfg.samples - len(vals)))
    s.round_avgs.append(statistics.fmean(vals) if vals else None)
    compute_score(s)


# ───────────────────────────── openvpn deep test / connect ─────────────────────────────

def openvpn_base() -> Optional[list]:
    exe = shutil.which("openvpn")
    if not exe and os.name == "nt":
        for p in (r"C:\Program Files\OpenVPN\bin\openvpn.exe", r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe"):
            if os.path.exists(p):
                exe = p
    if not exe:
        return None
    cmd = [exe]
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        cmd = [shutil.which("sudo"), "-n", exe]
    return cmd


def write_cfg_files(s: Server):
    tmp = tempfile.mkdtemp(prefix="vgtui_")
    cfgp, authp = os.path.join(tmp, "c.ovpn"), os.path.join(tmp, "auth.txt")
    Path(cfgp).write_text(s.ovpn)
    Path(authp).write_text("vpn\nvpn\n")
    return tmp, cfgp, authp


async def deep_test(s: Server, cfg: Config, speed=True):
    if not s.ovpn:
        s.deep_ok, s.deep_msg = None, "SSTP-only, no ovpn"
        return
    """Real OpenVPN connect (routes NOT pulled, so your traffic is untouched) + small speed test through the tunnel."""
    base = openvpn_base()
    if not base:
        s.deep_ok, s.deep_msg = None, "openvpn not installed"
        return
    tmp, cfgp, authp = write_cfg_files(s)
    routes = []
    if speed:
        try:
            infos = await asyncio.get_running_loop().run_in_executor(None, lambda: socket.getaddrinfo("speed.cloudflare.com", 443, socket.AF_INET))
            for ip in {i[4][0] for i in infos}:
                routes += ["--route", ip, "255.255.255.255", "vpn_gateway"]
        except Exception:
            routes = []
    args = ["--config", cfgp, "--auth-user-pass", authp, "--route-nopull", "--connect-timeout", "10",
            "--connect-retry-max", "1", "--verb", "3", "--script-security", "0"] + routes
    proc = await asyncio.create_subprocess_exec(*base, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    t0 = time.perf_counter()
    ok, msg = False, "timeout"
    try:
        while time.perf_counter() - t0 < cfg.deep_timeout:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), 1.0)
            except asyncio.TimeoutError:
                continue
            if not line:
                msg = "openvpn exited"
                break
            txt = line.decode(errors="replace").strip()
            if "Initialization Sequence Completed" in txt:
                ok = True
                break
            if any(k in txt for k in ("AUTH_FAILED", "password is required", "Permission denied", "Operation not permitted", "TLS Error", "Cannot ioctl")):
                msg = txt[-90:]
                if "password is required" in txt:
                    msg = "needs root: run with sudo or `sudo -v` first"
                break
        s.deep_ok = ok
        s.deep_s = time.perf_counter() - t0 if ok else None
        s.deep_msg = "connected" if ok else msg
        s.deep_mbps = None
        if ok and routes:
            await asyncio.sleep(1)
            try:
                async with httpx.AsyncClient(trust_env=False, timeout=12) as c:
                    t1, n = time.perf_counter(), 0
                    async with c.stream("GET", "https://speed.cloudflare.com/__down?bytes=3000000") as r:
                        async for chunk in r.aiter_bytes():
                            n += len(chunk)
                    dt = max(time.perf_counter() - t1, 1e-3)
                    s.deep_mbps = n * 8 / dt / 1e6
            except Exception:
                pass
    finally:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
    compute_score(s)


# ───────────────────────────── mirrors & fetching ─────────────────────────────

def _norm(u: str) -> str:
    return u if u.endswith("/") else u + "/"


def parse_mirror_text(text: str) -> list[str]:
    """Accepts README/HTML (full URLs), mirrors.json ([{IP,PORT}]) or mirrors.csv (IP,PORT,LOCATION)."""
    out = [_norm(m) for m in IP_URL_RE.findall(text)]
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("mirrors") or data.get("data") or [data]
        for d in data if isinstance(data, list) else []:
            if isinstance(d, dict):
                ip = str(d.get("IP") or d.get("ip") or "").strip()
                port = str(d.get("PORT") or d.get("port") or "").strip()
                if ip and port.isdigit():
                    out.append(f"http://{ip}:{port}/")
            elif isinstance(d, str):
                out += [_norm(m) for m in IP_URL_RE.findall(d)]
    except Exception:
        pass
    for m in re.finditer(r"^\s*((?:\d{1,3}\.){3}\d{1,3})\s*[,:;\t ]\s*(\d{2,5})\b", text, re.M):
        out.append(f"http://{m.group(1)}:{m.group(2)}/")
    return list(dict.fromkeys(out))


STALE_RE = re.compile(r"to\s+(\d{4})/(\d{2})/(\d{2})")


async def discover_mirrors(cfg: Config, status: Callable[[str], None]) -> list[str]:
    found: list[str] = [_norm(m) for m in cfg.mirrors]
    if EXTRA_MIRRORS_FILE.exists():
        found += parse_mirror_text(EXTRA_MIRRORS_FILE.read_text())
    reached, stale_days = 0, None
    async with httpx.AsyncClient(proxy=cfg.proxy, timeout=15, follow_redirects=True, headers=UA) as c:
        async def grab(u):
            try:
                r = await c.get(u)
                if r.status_code != 200:
                    return None, None
                m = STALE_RE.search(r.text)
                age = None
                if m:
                    age = (datetime.date.today() - datetime.date(*map(int, m.groups()))).days
                return parse_mirror_text(r.text), age
            except Exception:
                return None, None
        res = await asyncio.gather(*(grab(u) for u in MIRROR_SOURCES))
    for lst, age in res:
        if lst is not None:
            reached += 1
            found += lst
        if age is not None:
            stale_days = age if stale_days is None else min(stale_days, age)
    if reached == 0:
        status("Mirror list sources unreachable (GitHub/jsDelivr blocked?) - use --proxy or --mirror")
    elif stale_days is not None and stale_days > 3:
        status(f"WARNING: mirror list is {stale_days} days old (repo no longer updated) - mirrors are probably dead. Use --mirror / --proxy")
    cached = []
    if CACHE_FILE.exists():
        try:
            cached = json.loads(CACHE_FILE.read_text()).get("mirrors", [])
        except Exception:
            pass
    out = list(dict.fromkeys(found))
    if not out:
        out = cached  # yesterday's mirrors sometimes still live
    # official site is filtered in Iran: only try it when a proxy is configured or nothing else is known
    extra = OFFICIAL if (cfg.proxy or not out) else []
    return list(dict.fromkeys(out + extra))


FETCH_ERRORS: list[str] = []

SSTP_LIST_URLS = [
    "https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt",
    "https://cdn.jsdelivr.net/gh/Delta-Kronecker/Vpn-Gate@main/sstp_hosts.txt",
]


async def fetch_sstp_fallback(cfg: Config, status: Callable[[str], None]) -> list[dict]:
    """Live-tested SSTP hostnames (Delta-Kronecker/Vpn-Gate). Used when no mirror answers."""
    text = ""
    async with httpx.AsyncClient(proxy=cfg.proxy, timeout=20, follow_redirects=True, headers=UA) as c:
        for u in SSTP_LIST_URLS:
            try:
                r = await c.get(u)
                if r.status_code == 200 and "===" in r.text:
                    text = r.text
                    break
            except Exception as e:
                FETCH_ERRORS.append(f"fallback {u.split('/')[2]}: {type(e).__name__}")
    if not text:
        return []
    hosts, cur = [], ("Unknown", "")
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"=== (.+?) \((\w{2})\) - \d+ servers ===", line)
        if m:
            cur = (m.group(1), m.group(2))
        elif line and not line.startswith("#") and not line.startswith("="):
            hosts.append((line, cur))
    status(f"Fallback SSTP list: {len(hosts)} hosts - resolving DNS…")
    loop, sem, rows = asyncio.get_running_loop(), asyncio.Semaphore(40), []

    async def res(h, cc):
        async with sem:
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(h, 443, family=socket.AF_INET, type=socket.SOCK_STREAM), 6)
                ip = infos[0][4][0]
            except Exception:
                return
            rows.append({"IP": ip, "HostName": h, "CountryLong": cc[0], "CountryShort": cc[1], "_sstp_only": True,
                         "Score": "0", "Ping": "0", "Speed": "0", "NumVpnSessions": "0", "Uptime": "0",
                         "TotalUsers": "0", "TotalTraffic": "0", "LogType": "", "Operator": "", "Message": ""})
    await asyncio.gather(*(res(h, cc) for h, cc in hosts))
    if not rows:
        FETCH_ERRORS.append("fallback: DNS resolve failed for all hosts")
    return rows



async def fetch_all(cfg: Config, mirrors: list[str], status: Callable[[str], None]):
    rows: dict[str, dict] = {}
    ok_mirrors = 0
    async with httpx.AsyncClient(proxy=cfg.proxy, timeout=httpx.Timeout(40, connect=10), follow_redirects=True, headers=UA) as c:
        async def one(base):
            try:
                r = await c.get(base + "api/iphone/")
            except Exception as e:
                FETCH_ERRORS.append(f"{base.split('//')[1].rstrip('/')}: {type(e).__name__}")
                raise
            rows_ = parse_api(r.text)
            if not rows_:
                FETCH_ERRORS.append(f"{base.split('//')[1].rstrip('/')}: HTTP {r.status_code}, empty/invalid list")
            return rows_
        pending = {asyncio.create_task(one(m)) for m in mirrors}
        total, done_n, deadline = len(pending), 0, None
        while pending:
            tmo = None if deadline is None else max(0.0, deadline - time.time())
            done, pending = await asyncio.wait(pending, timeout=tmo, return_when=asyncio.FIRST_COMPLETED)
            for d in done:
                done_n += 1
                try:
                    got = d.result()
                except Exception:
                    got = []
                if got:
                    ok_mirrors += 1
                    deadline = deadline or time.time() + 10  # grace period for the other mirrors
                    for r in got:
                        old = rows.get(r.get("IP"))
                        if not old or _int(r.get("Score")) > _int(old.get("Score")):
                            rows[r.get("IP", "")] = r
            status(f"Fetching servers… {done_n}/{total} mirrors answered, {ok_mirrors} OK, {len(rows)} servers")
            if deadline is not None and time.time() >= deadline:
                break
        for p in pending:
            p.cancel()
    return list(rows.values()), ok_mirrors


# ───────────────────────────── persistence ─────────────────────────────

class History:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS results (ts INTEGER, ip TEXT, cc TEXT, country TEXT, proto TEXT, port INT,"
                        " lat REAL, jitter REAL, loss REAL, ovpn INT, sstp INT, l2tp INT, score REAL)")
        self.db.commit()

    def add(self, servers):
        ts = int(time.time())
        self.db.executemany("INSERT INTO results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            (ts, s.ip, s.cc, s.country, s.proto, s.port, s.lat, s.jitter, s.loss, int(bool(s.ovpn_ok)), int(bool(s.sstp_ok)),
             int(bool(s.l2tp_ok)), s.final) for s in servers if s.tested])
        self.db.commit()

    def recent(self, ip, n=12):
        return self.db.execute("SELECT ts,lat,jitter,loss,ovpn,sstp,l2tp,score FROM results WHERE ip=? ORDER BY ts DESC LIMIT ?", (ip, n)).fetchall()

    def by_hour(self, cc):
        return self.db.execute("SELECT strftime('%H',ts,'unixepoch','localtime') h, AVG(score), COUNT(*) FROM results WHERE cc=? GROUP BY h ORDER BY h", (cc,)).fetchall()


def load_prefs():
    try:
        d = json.loads(PREFS_FILE.read_text())
        return set(d.get("fav", [])), set(d.get("black", []))
    except Exception:
        return set(), set()


def save_prefs(fav, black):
    PREFS_FILE.write_text(json.dumps({"fav": sorted(fav), "black": sorted(black)}))


# ───────────────────────────── helpers for UI ─────────────────────────────

def color_for(v: float) -> str:
    return "green" if v >= 70 else "yellow" if v >= 45 else "red"


def score_bar(s: Server) -> Text:
    n = int(round(s.final / 10))
    t = Text("█" * n + "░" * (10 - n) + f" {int(s.final):>3}", style=color_for(s.final))
    if not s.tested:
        t.stylize("dim")
    return t


def mark(v) -> Text:
    return Text("✔", style="bold green") if v else Text("✘", style="red") if v is False else Text("·", style="dim")


def fmt_ms(v) -> Text:
    if v is None:
        return Text("—", style="dim")
    return Text(f"{v:.0f}", style="green" if v < 150 else "yellow" if v < 300 else "red")


def safe_name(s: Server, tuned=False) -> str:
    cc = re.sub(r"[^A-Za-z0-9]", "", s.country)[:20] or s.cc
    return f"vpngate_{cc}_{s.ip}_{s.proto}{s.port}{'_tuned' if tuned else ''}.ovpn"


def tune_ovpn(cfg: str) -> str:
    extra = "\n# --- tuned by vpngate-tui ---\nconnect-timeout 10\nconnect-retry-max 3\nserver-poll-timeout 10\n"
    return cfg.rstrip() + "\n" + extra


def copy_text(app: App, text: str) -> bool:
    try:
        app.copy_to_clipboard(text)
        return True
    except Exception:
        pass
    try:
        import pyperclip  # type: ignore
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def spark(vals):
    bars = "▁▂▃▄▅▆▇█"
    return "".join(bars[min(7, int(v / 12.5))] for v in vals)


# ───────────────────────────── modal screens ─────────────────────────────

class MenuScreen(ModalScreen[str]):
    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, title: str, entries: list[tuple[str, str]]):
        super().__init__()
        self.heading, self.entries = title, entries

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.heading, id="dlg-title")
            yield OptionList(*[Option(lbl, id=k) for k, lbl in self.entries], id="dlg-list")

    def on_mount(self):
        self.query_one(OptionList).focus()

    def on_option_list_option_selected(self, e: OptionList.OptionSelected):
        self.dismiss(e.option.id)

    def action_close(self):
        self.dismiss(None)


class InfoScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("c", "copy", "Copy")]

    def __init__(self, title: str, body: str, copy_payload: Optional[str] = None):
        super().__init__()
        self.heading, self.body, self.payload = title, body, copy_payload or body

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.heading, id="dlg-title")
            with VerticalScroll(id="info-scroll"):
                yield Static(Text(self.body))
            yield Label("Esc close  ·  c copy", id="dlg-hint")

    def action_close(self):
        self.dismiss(None)

    def action_copy(self):
        self.app.notify("Copied" if copy_text(self.app, self.payload) else "Clipboard unavailable", timeout=2)


# ───────────────────────────── main app ─────────────────────────────

class VPNGateApp(App):
    TITLE = "VPN Gate Scanner"
    SUB_TITLE = "tuned for Iran"
    CSS = """
    #bar { height: 3; }
    #search { width: 1fr; }
    #filterinfo { width: auto; padding: 1 2; color: $text-muted; }
    #main { height: 1fr; }
    #table { width: 1fr; border: round $primary; }
    #detail { width: 46; border: round $accent; padding: 0 1; }
    #status { height: 1; padding: 0 1; background: $panel; }
    #prog { height: 1; padding: 0 1; }
    MenuScreen, InfoScreen { align: center middle; }
    #dialog { width: 70; max-width: 95%; height: auto; max-height: 85%; border: thick $accent; background: $surface; padding: 1 2; }
    #dlg-title { text-style: bold; color: $accent; margin-bottom: 1; }
    #dlg-hint { color: $text-muted; margin-top: 1; }
    #info-scroll { height: auto; max-height: 28; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("t", "test", "Test all"),
        Binding("u", "stability", "Stability"),
        Binding("g", "deep_top", "Deep top"),
        Binding("d", "deep_one", "Deep 1", show=False),
        Binding("a", "auto_best", "Auto-best"),
        Binding("s", "save", "Save .ovpn"),
        Binding("l", "l2tp", "L2TP", show=False),
        Binding("k", "sstp", "SSTP", show=False),
        Binding("f", "fav", "★ Fav"),
        Binding("x", "black", "Blacklist", show=False),
        Binding("p", "cycle_filter", "Filter"),
        Binding("e", "export", "Export", show=False),
        Binding("c", "copy_ip", "Copy IP", show=False),
        Binding("ctrl+s", "save_top", "Save top10", show=False),
        Binding("z", "stop", "Stop", show=False),
        Binding("f2", "theme", "Theme", show=False),
        Binding("slash", "search", "Search"),
        Binding("escape", "blur_search", "", show=False),
        Binding("1", "sort('1')", "", show=False), Binding("2", "sort('2')", "", show=False),
        Binding("3", "sort('3')", "", show=False), Binding("4", "sort('4')", "", show=False),
        Binding("5", "sort('5')", "", show=False),
    ]

    def __init__(self, cfg: Config):
        super().__init__()
        self.cfg = cfg
        self.servers: dict[str, Server] = {}
        self.mirrors: list[str] = []
        self.fav, self.black = load_prefs()
        self.history = History(DB_FILE)
        self.filter_idx, self.sort_key, self.query = 0, "1", ""
        self.selected_ip: Optional[str] = None
        self.dirty = False
        self.mirror_stats = (0, 0)

    # ---- layout
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="bar"):
            yield Input(placeholder="/  search country · IP · host …", id="search")
            yield Static(id="filterinfo")
        with Horizontal(id="main"):
            yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
            yield Static(id="detail")
        yield Static(id="status")
        yield ProgressBar(total=100, show_eta=False, id="prog")
        yield Footer()

    def on_mount(self):
        t = self.query_one("#table", DataTable)
        t.border_title = "Servers"
        self.query_one("#detail").border_title = "Details"
        for label, w in [("★", 1), ("#", 3), ("Country", 22), ("IP", 15), ("Proto", 5), ("Port", 5), ("Ping", 5), ("Jit", 4),
                         ("Loss", 5), ("OVPN", 4), ("SSTP", 4), ("L2TP", 4), ("Deep", 4), ("Score", 14), ("Mbps", 6), ("Sess", 5)]:
            t.add_column(label, width=w)
        self.set_interval(0.4, self._tick)
        self._load_cache()
        self.action_refresh()
        t.focus()

    # ---- status helpers
    def set_status(self, msg: str, busy=False):
        n_t = sum(1 for s in self.servers.values() if s.tested)
        self.query_one("#status", Static).update(
            Text(f" {msg}   │   servers {len(self.servers)} · tested {n_t} · mirrors OK {self.mirror_stats[0]}/{self.mirror_stats[1]}"
                 f" · sort: {SORTS[self.sort_key]}"))
        self.query_one("#filterinfo", Static).update(Text(f"Filter: {FILTERS[self.filter_idx]}"))

    def progress(self, done: int, total: int):
        bar = self.query_one("#prog", ProgressBar)
        bar.display = total > 0
        bar.update(total=max(total, 1), progress=done)

    # ---- data
    def _load_cache(self):
        if self.cfg.import_path:
            return
        try:
            d = json.loads(CACHE_FILE.read_text())
            self._ingest(d.get("rows", []))
            self.mirrors = d.get("mirrors", [])
            self.set_status("Loaded cached list (offline) - refreshing…")
        except Exception:
            pass

    def _ingest(self, rows: list[dict]):
        new: dict[str, Server] = {}
        for r in rows:
            s = Server.from_row(r)
            if s:
                new[s.ip] = self.servers.get(s.ip, s)
                compute_score(new[s.ip])
        self.servers = new
        self.dirty = True

    def action_refresh(self):
        self.run_worker(self._load(), group="fetch", exclusive=True)

    async def _load(self):
        self.set_status("Discovering today's mirrors…", True)
        if self.cfg.import_path:
            rows = parse_api(Path(self.cfg.import_path).read_text(errors="replace"))
            self._ingest(rows)
            self.set_status(f"Imported {len(rows)} servers from file")
            return
        mirrors = await discover_mirrors(self.cfg, self.set_status)
        self.mirrors = mirrors
        self.mirror_stats = (0, len(mirrors))
        self.set_status(f"Found {len(mirrors)} mirror addresses - fetching…", True)
        rows, ok = await fetch_all(self.cfg, mirrors, self.set_status)
        self.mirror_stats = (ok, len(mirrors))
        if not rows:
            self.set_status("No mirror answered - loading fallback SSTP list…", True)
            rows = await fetch_sstp_fallback(self.cfg, self.set_status)
            if rows:
                self.notify(f"Mirrors dead: using fallback SSTP list ({len(rows)} servers, SSTP only)", severity="warning", timeout=8)
        if rows:
            self._ingest(rows)
            try:
                CACHE_FILE.write_text(json.dumps({"ts": time.time(), "mirrors": [m for m in mirrors if m not in OFFICIAL], "rows": rows}))
            except Exception:
                pass
            self.set_status(f"Got {len(rows)} servers from {ok} mirrors. Press t to test.")
            self.notify(f"{len(rows)} servers from {ok} mirrors", timeout=3)
        else:
            why = " | ".join(FETCH_ERRORS[:5]) or "no mirror addresses were found at all"
            (APP_DIR / "last_error.txt").write_text("\n".join(FETCH_ERRORS) or why, encoding="utf-8")
            self.set_status(f"No mirror answered: {why}")
            self.notify("No mirror reachable! Use --proxy / --mirror / --import", severity="error", timeout=8)

    # ---- table
    def _tick(self):
        if self.dirty:
            self.dirty = False
            self.refresh_table()

    def visible(self) -> list[Server]:
        q, f = self.query.lower(), FILTERS[self.filter_idx]
        out = []
        for s in self.servers.values():
            if (s.ip in self.black) != (f == "Blacklist"):
                continue
            if q and q not in f"{s.country} {s.cc} {s.ip} {s.host}".lower():
                continue
            if f == "TCP" and s.proto != "tcp":
                continue
            if f == "UDP" and s.proto != "udp":
                continue
            if f == "TCP/443" and not (s.proto == "tcp" and s.port == 443):
                continue
            if f == "SSTP ✔" and not s.sstp_ok:
                continue
            if f == "L2TP ✔" and not s.l2tp_ok:
                continue
            if f == "OpenVPN ✔" and not s.ovpn_ok:
                continue
            if f == "★ Favorites" and s.ip not in self.fav:
                continue
            out.append(s)
        k = self.sort_key
        inf = float("inf")
        if k == "1":
            out.sort(key=lambda s: -s.final)
        elif k == "2":
            out.sort(key=lambda s: s.lat if s.lat is not None else inf)
        elif k == "3":
            out.sort(key=lambda s: s.jitter if s.ok_samples else inf)
        elif k == "4":
            out.sort(key=lambda s: -s.speed)
        else:
            out.sort(key=lambda s: s.country)
        return out

    def refresh_table(self):
        t = self.query_one("#table", DataTable)
        rows = self.visible()
        keep = self.selected_ip
        t.clear()
        for i, s in enumerate(rows, 1):
            t.add_row(
                Text("★", style="yellow") if s.ip in self.fav else "", str(i), f"{flag(s.cc)} {s.country}"[:24], s.ip, s.proto.upper(), str(s.port),
                fmt_ms(s.lat), fmt_ms(s.jitter) if s.ok_samples else Text("—", style="dim"),
                Text(f"{s.loss:.0f}%", style="green" if s.loss == 0 else "yellow" if s.loss < 40 else "red") if s.tested else Text("·", style="dim"),
                mark(s.ovpn_ok),
                (Text("tls", style="yellow") if (s.tls_ok and not s.sstp_ok) else mark(s.sstp_ok)),
                mark(s.l2tp_ok), mark(s.deep_ok), score_bar(s), f"{s.speed / 1e6:.0f}", str(s.sessions), key=s.ip)
        ips = [s.ip for s in rows]
        if keep in ips:
            t.move_cursor(row=ips.index(keep), animate=False)
        elif rows:
            self.selected_ip = rows[0].ip
        self.set_status("Ready")
        self.show_detail()

    @on(DataTable.RowHighlighted)
    def _hl(self, e: DataTable.RowHighlighted):
        if e.row_key and e.row_key.value:
            self.selected_ip = e.row_key.value
            self.show_detail()

    def current(self) -> Optional[Server]:
        return self.servers.get(self.selected_ip or "")

    def show_detail(self):
        d = self.query_one("#detail", Static)
        s = self.current()
        if not s:
            d.update(Text("No server selected"))
            return
        t = Text()
        t.append(f"{flag(s.cc)}  {s.country}\n", style="bold")
        t.append(f"{s.ip}  ({s.host})\n", style="cyan")
        t.append(f"Score  ").append_text(score_bar(s)).append("\n\n")
        t.append(f"OpenVPN   {s.proto.upper()}:{s.port}   ").append_text(mark(s.ovpn_ok)).append("\n")
        t.append("SSTP      443   ").append_text(mark(s.sstp_ok)).append(f"  TLS {'ok' if s.tls_ok else '—'}"
                                                                           f"{f' {s.tls_ms:.0f}ms' if s.tls_ms else ''}\n")
        t.append("L2TP/IPsec 500  ").append_text(mark(s.l2tp_ok)).append(f"{f' {s.l2tp_ms:.0f}ms' if s.l2tp_ms else ''}\n\n")
        if s.tested:
            t.append(f"Latency   {s.lat:.0f} ms\n" if s.lat is not None else "Latency   —\n")
            t.append(f"Jitter    {s.jitter:.1f} ms\nLoss      {s.loss:.0f}%  ({len(s.samples)} samples)\n")
            if len(s.round_avgs) > 1:
                t.append("Rounds    " + " ".join("✘" if v is None else f"{v:.0f}" for v in s.round_avgs) + " ms\n")
        else:
            t.append("Not tested yet - press t\n", style="dim")
        t.append(f"Iran-compat {compat_score(s):.0f}/100\n")
        if s.deep_ok is not None or s.deep_msg:
            t.append(f"\nDeep: {s.deep_msg}")
            if s.deep_s:
                t.append(f"  {s.deep_s:.1f}s")
            if s.deep_mbps:
                t.append(f"  {s.deep_mbps:.1f} Mbps")
            t.append("\n")
        t.append(f"\nReported speed {s.speed / 1e6:.0f} Mbps · sessions {s.sessions}\n")
        t.append(f"Uptime {s.uptime // 86400000}d · users {s.users:,}\nLog: {s.logtype or '—'}\nOperator: {s.operator or '—'}\n")
        d.update(t)

    @on(DataTable.RowSelected)
    def _selected(self, e: DataTable.RowSelected):
        self.open_menu()

    # ---- search / filter / sort
    def action_search(self):
        self.query_one("#search", Input).focus()

    def action_blur_search(self):
        self.query_one("#table", DataTable).focus()

    @on(Input.Changed, "#search")
    def _search_changed(self, e: Input.Changed):
        self.query = e.value
        self.dirty = True

    @on(Input.Submitted, "#search")
    def _search_submit(self):
        self.query_one("#table", DataTable).focus()

    def action_cycle_filter(self):
        self.filter_idx = (self.filter_idx + 1) % len(FILTERS)
        self.dirty = True

    def action_sort(self, key: str):
        self.sort_key = key
        self.dirty = True

    def action_theme(self):
        try:
            avail = [x for x in THEMES if x in self.available_themes]
            self.theme = avail[(avail.index(self.theme) + 1) % len(avail)] if self.theme in avail else avail[0]
        except Exception:
            pass

    # ---- testing
    def action_test(self):
        if not self.servers:
            return self.notify("No servers yet", severity="warning")
        self.run_worker(self._run_quick(), group="test", exclusive=True)

    async def _run_quick(self):
        targets = [s for s in self.servers.values() if s.ip not in self.black]
        sem, done, total = asyncio.Semaphore(self.cfg.concurrency), 0, len(targets)

        async def one(s):
            nonlocal done
            async with sem:
                await quick_test_one(s, self.cfg)
            done += 1
            self.dirty = True
            self.progress(done, total)
            self.set_status(f"Testing… {done}/{total}  (z = stop)", True)

        try:
            await asyncio.gather(*(one(s) for s in targets))
        finally:
            self.history.add(targets)
            self.progress(0, 0)
        alive = sum(1 for s in targets if s.ovpn_ok or s.sstp_ok or s.l2tp_ok)
        self.set_status(f"Done - {alive}/{total} servers answered a real handshake")
        self.dirty = True
        self.notify(f"{alive}/{total} servers reachable", timeout=4)

    def action_stability(self):
        self.run_worker(self._run_stability(), group="test", exclusive=True)

    async def _run_stability(self):
        top = sorted([s for s in self.servers.values() if s.tested and (s.ovpn_ok or s.sstp_ok or s.l2tp_ok) and s.ip not in self.black],
                     key=lambda s: -s.final)[: self.cfg.stability_top]
        if not top:
            return self.notify("Run the quick test (t) first", severity="warning")
        for s in top:
            s.round_avgs = s.round_avgs[:1]
        total = self.cfg.rounds - 1
        for r in range(total):
            for left in range(self.cfg.interval, 0, -1):
                self.set_status(f"Stability round {r + 1}/{total}: waiting {left}s…  (z = stop)", True)
                self.progress(r * self.cfg.interval + (self.cfg.interval - left), total * self.cfg.interval)
                await asyncio.sleep(1)
            sem = asyncio.Semaphore(self.cfg.concurrency)

            async def one(s):
                async with sem:
                    await stability_round(s, self.cfg)
            await asyncio.gather(*(one(s) for s in top))
            self.dirty = True
        self.history.add(top)
        self.progress(0, 0)
        self.set_status(f"Stability test finished on top {len(top)}")
        self.notify("Stability test finished", timeout=4)

    def action_deep_top(self):
        if not openvpn_base():
            return self.notify("openvpn is not installed", severity="error")
        self.run_worker(self._run_deep(None), group="test", exclusive=True)

    def action_deep_one(self):
        s = self.current()
        if s:
            if not openvpn_base():
                return self.notify("openvpn is not installed", severity="error")
            self.run_worker(self._run_deep([s]), group="test", exclusive=True)

    async def _run_deep(self, targets):
        if targets is None:
            targets = sorted([s for s in self.servers.values() if s.tested and (s.ovpn_ok) and s.ip not in self.black],
                             key=lambda s: -s.final)[: self.cfg.deep_top]
        if not targets:
            return self.notify("Run the quick test (t) first", severity="warning")
        for i, s in enumerate(targets, 1):
            self.set_status(f"Deep test {i}/{len(targets)}: {s.ip} ({s.country}) - real OpenVPN connect…  (z = stop)", True)
            self.progress(i - 1, len(targets))
            await deep_test(s, self.cfg)
            self.dirty = True
        self.progress(0, 0)
        ok = sum(1 for s in targets if s.deep_ok)
        self.set_status(f"Deep test finished: {ok}/{len(targets)} connected")
        self.notify(f"Deep: {ok}/{len(targets)} connected", timeout=5)

    def action_auto_best(self):
        self.run_worker(self._auto_best(), group="test", exclusive=True)

    async def _auto_best(self):
        if not openvpn_base():
            return self.notify("openvpn is not installed - auto connect needs it", severity="error")
        if not any(s.tested for s in self.servers.values()):
            await self._run_quick()
        cands = sorted([s for s in self.servers.values() if s.tested and s.ovpn_ok and s.ip not in self.black], key=lambda s: -s.final)[:8]
        for i, s in enumerate(cands, 1):
            self.set_status(f"Auto-best: trying {s.ip} ({s.country}) {i}/{len(cands)}…", True)
            await deep_test(s, self.cfg, speed=False)
            self.dirty = True
            if s.deep_ok:
                self.notify(f"Connecting to {s.country} {s.ip}", timeout=3)
                self.call_later(self.connect_now, s)
                return
        self.notify("No server passed the real connect test", severity="warning")

    def action_stop(self):
        self.workers.cancel_group(self, "test")
        self.progress(0, 0)
        self.set_status("Stopped")

    # ---- actions on a server
    def open_menu(self):
        s = self.current()
        if not s:
            return
        entries = [
            ("save", "⬇  Save .ovpn (original)"), ("save_tuned", "⬇  Save .ovpn (tuned: short timeouts)"),
            ("connect", "🔌 Connect now with OpenVPN"), ("deep", "🧪 Deep test (real connect + speed)"),
            ("l2tp", "📡 L2TP/IPsec details"), ("sstp", "🔒 SSTP details"), ("copy", "📋 Copy IP"),
            ("fav", "★  Toggle favorite"), ("black", "🚫 Toggle blacklist"), ("hist", "📈 History"),
        ]
        self.push_screen(MenuScreen(f"{flag(s.cc)} {s.country} · {s.ip}", entries), self._menu_result)

    def _menu_result(self, key):
        s = self.current()
        if not key or not s:
            return
        {"save": lambda: self.save(s), "save_tuned": lambda: self.save(s, True), "connect": lambda: self.connect_now(s),
         "deep": self.action_deep_one, "l2tp": self.action_l2tp, "sstp": self.action_sstp, "copy": self.action_copy_ip,
         "fav": self.action_fav, "black": self.action_black, "hist": self.show_history}[key]()

    def save(self, s: Server, tuned=False):
        if not s.ovpn:
            self.notify("SSTP-only server (from fallback list): no .ovpn. Use the SSTP option.", severity="warning", timeout=6)
            return
        try:
            self.cfg.out_dir.mkdir(parents=True, exist_ok=True)
            p = self.cfg.out_dir / safe_name(s, tuned)
            p.write_text(tune_ovpn(s.ovpn) if tuned else s.ovpn)
            self.notify(f"Saved: {p}", timeout=6)
        except Exception as e:
            self.notify(f"Save failed: {e}", severity="error")

    def action_save(self):
        s = self.current()
        if s:
            self.save(s)

    def action_save_top(self):
        rows = [s for s in self.visible() if s.tested and s.ovpn_ok][:10]
        for s in rows:
            self.save(s)
        self.notify(f"Saved {len(rows)} configs to {self.cfg.out_dir}", timeout=6)

    def connect_now(self, s: Server):
        base = openvpn_base()
        if not base:
            return self.notify("openvpn is not installed", severity="error")
        tmp, cfgp, authp = write_cfg_files(s)
        with self.suspend():
            print(f"\n=== Connecting to {s.country} {s.ip} ({s.proto}:{s.port}) - Ctrl+C to disconnect ===\n")
            try:
                subprocess.run(base + ["--config", cfgp, "--auth-user-pass", authp])
            except KeyboardInterrupt:
                pass
        shutil.rmtree(tmp, ignore_errors=True)

    def action_l2tp(self):
        s = self.current()
        if not s:
            return
        body = (f"L2TP/IPsec  -  {s.country}\n\nServer:      {s.ip}\nIPsec PSK:   vpn\nUsername:    vpn\nPassword:    vpn\n"
                f"Port:        UDP 500 / 4500 (IKE, NAT-T)\n\nProbe: {'IKE answered ✔' if s.l2tp_ok else 'no IKE answer ✘' if s.l2tp_ok is False else 'not tested'}"
                f"{f' ({s.l2tp_ms:.0f} ms)' if s.l2tp_ms else ''}\n\nNote: UDP 500/4500 is often throttled or blocked in Iran, "
                "so prefer SSTP or OpenVPN-TCP/443.\nWindows behind NAT needs registry AssumeUDPEncapsulationContextOnSendRule=2.")
        self.push_screen(InfoScreen("L2TP/IPsec", body, f"Server: {s.ip}\nPSK: vpn\nUser: vpn\nPass: vpn"))

    def action_sstp(self):
        s = self.current()
        if not s:
            return
        body = (f"SSTP  -  {s.country}\n\nServer (use hostname!): {s.sstp_host}\nIP (backup):            {s.ip}\nPort:                   443\n"
                f"Username:               vpn\nPassword:               vpn\n\nProbe: "
                f"{'real SSTP handshake ✔' if s.sstp_ok else ('TLS ok but not SSTP' if s.tls_ok else 'no answer ✘') if s.sstp_ok is False else 'not tested'}"
                f"{f' (TLS {s.tls_ms:.0f} ms)' if s.tls_ms else ''}\n\nWindows: Settings → VPN → Add → type 'SSTP'.\n"
                "The certificate is issued for *.opengw.net, so connect with the hostname, not the raw IP.\n"
                "SSTP looks like normal HTTPS on 443, so it usually survives DPI best.")
        self.push_screen(InfoScreen("SSTP", body, f"Server: {s.sstp_host}\nUser: vpn\nPass: vpn"))

    def show_history(self):
        s = self.current()
        if not s:
            return
        lines = [f"{s.country} · {s.ip}\n", "Last results (newest first):"]
        for ts, lat, jit, loss, o, st, l2, sc in self.history.recent(s.ip):
            lines.append(f"{time.strftime('%m-%d %H:%M', time.localtime(ts))}  ping {lat or 0:5.0f}  jit {jit or 0:4.0f}  loss {loss or 0:3.0f}%  "
                         f"ovpn {'✔' if o else '✘'} sstp {'✔' if st else '✘'} l2tp {'✔' if l2 else '✘'}  score {sc:3.0f}")
        hrs = self.history.by_hour(s.cc)
        if hrs:
            lines += ["", f"Average score for {s.country} by hour of day:",
                      "".join(f"{h}h " for h, _, _ in hrs), spark([v for _, v, _ in hrs]), "(run tests at different hours to build this up)"]
        self.push_screen(InfoScreen("History", "\n".join(lines)))

    def action_fav(self):
        s = self.current()
        if s:
            self.fav ^= {s.ip}
            save_prefs(self.fav, self.black)
            self.dirty = True

    def action_black(self):
        s = self.current()
        if s:
            self.black ^= {s.ip}
            save_prefs(self.fav, self.black)
            self.dirty = True

    def action_copy_ip(self):
        s = self.current()
        if s:
            self.notify("IP copied" if copy_text(self, s.ip) else s.ip, timeout=2)

    def action_export(self):
        rows = self.visible()
        data = [{"country": s.country, "cc": s.cc, "ip": s.ip, "host": s.host, "proto": s.proto, "port": s.port,
                 "ping_ms": s.lat, "jitter_ms": s.jitter, "loss_pct": s.loss, "openvpn": s.ovpn_ok, "sstp": s.sstp_ok,
                 "l2tp": s.l2tp_ok, "deep": s.deep_ok, "deep_mbps": s.deep_mbps, "score": round(s.final, 1)} for s in rows]
        self.cfg.out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M")
        jp, cp = self.cfg.out_dir / f"vpngate_{stamp}.json", self.cfg.out_dir / f"vpngate_{stamp}.csv"
        jp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        with cp.open("w", newline="") as f:
            if data:
                w = csv.DictWriter(f, fieldnames=list(data[0]))
                w.writeheader()
                w.writerows(data)
        self.notify(f"Exported {len(data)} rows → {jp.name}, {cp.name}", timeout=6)


def main():
    global USE_FLAGS
    ap = argparse.ArgumentParser(description="VPN Gate scanner TUI (tuned for Iran)")
    ap.add_argument("--proxy", help="proxy for fetching mirrors, e.g. socks5://127.0.0.1:1080 or http://127.0.0.1:8080")
    ap.add_argument("--mirror", action="append", default=[], help="extra mirror URL (repeatable), e.g. http://1.2.3.4:5555/")
    ap.add_argument("--import", dest="import_path", help="load a saved /api/iphone/ CSV instead of fetching")
    ap.add_argument("--out", help="folder for saved .ovpn / exports")
    ap.add_argument("--samples", type=int, default=5, help="TCP/UDP samples per server (default 5)")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-probe timeout seconds (default 4)")
    ap.add_argument("--rounds", type=int, default=3, help="stability rounds (default 3)")
    ap.add_argument("--interval", type=int, default=30, help="seconds between stability rounds (default 30)")
    ap.add_argument("--no-flags", action="store_true", help="show [CC] instead of flag emoji (e.g. old Windows consoles)")
    a = ap.parse_args()
    USE_FLAGS = not a.no_flags
    cfg = Config(proxy=a.proxy, mirrors=a.mirror, import_path=a.import_path, samples=a.samples, timeout=a.timeout,
                 rounds=a.rounds, interval=a.interval)
    if a.out:
        cfg.out_dir = Path(a.out).expanduser()
    VPNGateApp(cfg).run()


if __name__ == "__main__":
    main()
