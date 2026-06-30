#!/usr/bin/env python3
"""
xbox_host_picker.py
===================

Command-line tool that finds Xbox consoles on your LAN and randomly picks
one to be the Halo System Link host.

Usage:
    python xbox_host_picker.py
    python xbox_host_picker.py --list
    python xbox_host_picker.py --subnet 10.0.0.0/24 --seed 42

Run with sudo on Linux/macOS for the most reliable scan (scapy ARP sweep).
Falls back to ping sweep automatically if scapy is unavailable or lacks root.
"""

import argparse
import ipaddress
import platform
import random
import re
import secrets
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor


XBOX_OUIS = {
    "00:50:F2", "00:0D:3A", "00:12:5A", "00:15:5D", "00:17:FA", "00:1D:D8",
    "00:22:48", "00:25:AE", "60:45:BD", "7C:ED:8D", "98:5F:D3", "9C:AA:1B",
    "C8:3F:26",
}

# ANSI colour helpers — disabled when stdout is not a terminal
_TTY = sys.stdout.isatty()

def _c(code, t): return f"\033[{code}m{t}\033[0m" if _TTY else t
def green(t):    return _c("32;1", t)
def yellow(t):   return _c("33;1", t)
def dim(t):      return _c("2",    t)
def bold(t):     return _c("1",    t)
def red(t):      return _c("31",   t)


# ── scan backend ──────────────────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    mac = mac.replace("-", ":").strip().upper()
    return ":".join(p.zfill(2) for p in mac.split(":") if p != "")


def oui_of(mac: str) -> str:
    return ":".join(normalize_mac(mac).split(":")[:3])


def is_xbox(mac: str) -> bool:
    return bool(mac) and oui_of(mac) in XBOX_OUIS


def get_local_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip, ipaddress.ip_network(local_ip + "/24", strict=False)


def scan_scapy(net):
    from scapy.all import ARP, Ether, srp
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=2, retry=1, verbose=0)
    return [(rcv.psrc, normalize_mac(rcv.hwsrc)) for _, rcv in answered]


def _ping(ip):
    system = platform.system()
    cmd = ["ping", "-n" if system == "Windows" else "-c", "1", str(ip)]
    if system == "Linux":
        cmd[1:1] = ["-W", "1"]
    elif system == "Darwin":
        cmd[1:1] = ["-t", "1"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=3)
    except Exception:
        pass


def read_arp_table():
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:
        return []
    pat = re.compile(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?.*?"
                     r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
    hosts = []
    for line in out.splitlines():
        m = pat.search(line)
        if m:
            hosts.append((m.group(1), normalize_mac(m.group(2))))
    return hosts


def scan_ping(net):
    targets = list(net.hosts())
    with ThreadPoolExecutor(max_workers=min(128, len(targets) or 1)) as ex:
        list(ex.map(_ping, targets))
    return read_arp_table()


def discover(net, force_ping=False):
    hosts, note = [], ""
    if not force_ping:
        try:
            hosts = scan_scapy(net)
        except ImportError:
            note = "scapy not installed — using ping sweep"
        except PermissionError:
            note = "scapy needs root — using ping sweep (try sudo)"
        except Exception as e:
            note = f"scapy failed ({e}) — using ping sweep"
    if not hosts:
        hosts = scan_ping(net)
    seen, uniq = set(), []
    for ip, mac in hosts:
        if mac and mac != "00:00:00:00:00:00" and (ip, mac) not in seen:
            seen.add((ip, mac))
            uniq.append((ip, mac))
    uniq.sort(key=lambda h: ipaddress.ip_address(h[0]))
    return uniq, note


def hostname_for(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except Exception:
        return ""


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="xbox_host_picker.py",
        description="Find Xbox consoles on your LAN and pick a Halo System Link host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s                             scan and pick a host
  %(prog)s --list                      scan and list, don't pick
  %(prog)s --all                       include non-Xbox devices too
  %(prog)s --subnet 10.0.0.0/24       scan a specific subnet
  %(prog)s --add 192.168.1.50         force-include an extra IP
  %(prog)s --exclude 192.168.1.1      skip an IP (e.g. your router)
  %(prog)s --seed 7                   reproducible pick (tournaments)
        """,
    )
    p.add_argument("--subnet", metavar="CIDR",
                   help="Subnet to scan (default: auto-detect your /24)")
    p.add_argument("--list", action="store_true",
                   help="List found consoles without picking a host")
    p.add_argument("--all", dest="all_hosts", action="store_true",
                   help="Include all live hosts, not just Xbox MACs")
    p.add_argument("--add", metavar="IP", action="append", default=[],
                   help="Force-include an IP (repeatable)")
    p.add_argument("--exclude", metavar="IP", action="append", default=[],
                   help="Exclude an IP from the pool (repeatable)")
    p.add_argument("--ping-only", action="store_true",
                   help="Skip scapy, use ping sweep only")
    p.add_argument("--seed", metavar="N", type=int,
                   help="Integer seed for reproducible picks (disables secrets RNG)")
    return p.parse_args()


def main():
    args = parse_args()

    # ── subnet ────────────────────────────────────────────────────────────────
    if args.subnet:
        try:
            net = ipaddress.ip_network(args.subnet, strict=False)
        except ValueError as e:
            print(red(f"error: bad subnet — {e}"), file=sys.stderr)
            sys.exit(1)
    else:
        try:
            _, net = get_local_subnet()
        except Exception as e:
            print(red(f"error: could not detect local subnet — {e}"), file=sys.stderr)
            sys.exit(1)

    # ── scan ──────────────────────────────────────────────────────────────────
    print(dim(f"Scanning {net} …"), flush=True)
    hosts, note = discover(net, force_ping=args.ping_only)
    if note:
        print(dim(f"  {note}"))

    # Merge force-added IPs; they bypass the Xbox filter since user asked for them
    known_ips = {ip for ip, _ in hosts}
    force_added: set[str] = set()
    for raw in args.add:
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            print(red(f"warning: invalid --add address '{raw}', skipping"),
                  file=sys.stderr)
            continue
        if ip not in known_ips:
            hosts.append((ip, ""))
            known_ips.add(ip)
        force_added.add(ip)

    # Xbox filter (force-added IPs are always included)
    if not args.all_hosts:
        hosts = [(ip, mac) for ip, mac in hosts
                 if ip in force_added or is_xbox(mac)]

    # Exclude list
    exclude_set: set[str] = set()
    for raw in args.exclude:
        try:
            exclude_set.add(str(ipaddress.ip_address(raw)))
        except ValueError:
            print(red(f"warning: invalid --exclude address '{raw}', skipping"),
                  file=sys.stderr)
    hosts = [(ip, mac) for ip, mac in hosts if ip not in exclude_set]

    # ── resolve hostnames concurrently ────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=min(16, len(hosts) or 1)) as ex:
        hostnames = list(ex.map(lambda h: hostname_for(h[0]), hosts))

    entries = [
        {"ip": ip, "mac": mac, "hostname": hn, "name": hn or ip}
        for (ip, mac), hn in zip(hosts, hostnames)
    ]

    # ── display ───────────────────────────────────────────────────────────────
    print()
    if not entries:
        print(dim("No consoles found."))
        if not args.all_hosts:
            print(dim("  Tip: try --all to include non-Xbox devices."))
        sys.exit(0)

    print(bold(f"Found {len(entries)} console(s):"))

    name_w = max(len(e["name"]) for e in entries)
    ip_w   = max(len(e["ip"])   for e in entries)

    for i, e in enumerate(entries, 1):
        tag     = green("[Xbox]") if is_xbox(e["mac"]) else dim("[?]   ")
        mac_str = e["mac"] if e["mac"] else dim("??:??:??:??:??:??")
        forced  = dim(" +") if e["ip"] in force_added else "  "
        print(f"  {dim(str(i) + '.')}{forced} "
              f"{e['name']:<{name_w}}  "
              f"{dim(e['ip']):<{ip_w}}  "
              f"{mac_str}  "
              f"{tag}")

    if args.list:
        sys.exit(0)

    # ── pick ──────────────────────────────────────────────────────────────────
    print()
    if args.seed is not None:
        random.seed(args.seed)
        winner = random.choice(entries)
        print(dim(f"(seeded pick — seed={args.seed})"))
    else:
        winner = secrets.choice(entries)

    label = f"{winner['name']}  ({winner['ip']})" if winner["hostname"] else winner["ip"]
    print(yellow(f"★  HOST:  {label}"))


if __name__ == "__main__":
    main()
