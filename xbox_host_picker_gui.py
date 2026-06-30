#!/usr/bin/env python3
"""
xbox_host_picker_gui.py
=======================

A desktop GUI that finds Xbox consoles on your LAN and randomly picks one to be
the Halo System Link host -- Halo 2 (original Xbox) or Halo 3 (Xbox 360).

Eight consoles are drawn as little Xboxes. Auto-fill them by scanning the LAN,
or type names/IPs in by hand. Click a console to toggle it on/off. Hit
"Pick Host" for a roulette-style spin that lights up a random eligible Xbox.

Run:
    python xbox_host_picker_gui.py

Scanning notes:
  * Most reliable with scapy:  pip install scapy   (run with sudo on Linux/mac)
  * Without scapy it falls back to a ping sweep + your system ARP table.
  * Consoles must be powered on and on the same switch. OG Xboxes sometimes
    only appear once a System Link game (e.g. Halo 2's lobby) is loaded.

Change NUM_SLOTS / COLUMNS below to lay out a different number of consoles.
"""

import ipaddress
import platform
import queue
import random
import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import tkinter as tk
from tkinter import font as tkfont

NUM_SLOTS = 8
COLUMNS = 4

# --- Microsoft / Xbox MAC OUI prefixes (first three octets). Edit freely. -----
XBOX_OUIS = {
    "00:50:F2", "00:0D:3A", "00:12:5A", "00:15:5D", "00:17:FA", "00:1D:D8",
    "00:22:48", "00:25:AE", "60:45:BD", "7C:ED:8D", "98:5F:D3", "9C:AA:1B",
    "C8:3F:26",
}

# --- Theme ---------------------------------------------------------------------
BG     = "#0a0f0d"
PANEL  = "#101a14"
ACCENT = "#4cff9f"   # Halo / Xbox green
DIM    = "#5f7d6c"
TEXT   = "#d4efe0"
WIN    = "#ffd447"   # gold for the chosen host
LED_ON = "#39ff14"


# ============================== scan backend ==================================
def normalize_mac(mac: str) -> str:
    mac = mac.replace("-", ":").strip().upper()
    return ":".join(p.zfill(2) for p in mac.split(":") if p != "")


def oui_of(mac: str) -> str:
    return ":".join(normalize_mac(mac).split(":")[:3])


def is_xbox(mac: str) -> bool:
    return oui_of(mac) in XBOX_OUIS


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
            note = "scapy not installed - used ping sweep"
        except PermissionError:
            note = "scapy needs root - used ping sweep (try sudo)"
        except Exception as e:
            note = f"scapy failed ({e}) - used ping sweep"
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


# ============================ drawing helpers =================================
def round_rect(c, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


# ============================ custom widgets ==================================
# Native macOS tk.Button ignores bg/fg, so we build buttons from a Frame+Label.
# These honor colors identically on Windows, Linux and macOS.
class FlatButton(tk.Frame):
    def __init__(self, parent, text, command, bg, fg, hover, font,
                 padx=12, pady=5, border="#27402f"):
        super().__init__(parent, bg=bg, highlightthickness=1,
                         highlightbackground=border, highlightcolor=border)
        self.command = command
        self.bg, self.hover, self.fg = bg, hover, fg
        self.enabled = True
        self.lbl = tk.Label(self, text=text, bg=bg, fg=fg, font=font,
                            padx=padx, pady=pady, cursor="hand2")
        self.lbl.pack()
        for w in (self, self.lbl):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", self._enter)
            w.bind("<Leave>", self._leave)

    def _click(self, _e):
        if self.enabled and self.command:
            self.command()

    def _enter(self, _e):
        if self.enabled:
            self.configure(bg=self.hover)
            self.lbl.configure(bg=self.hover)

    def _leave(self, _e):
        self.configure(bg=self.bg)
        self.lbl.configure(bg=self.bg)

    def set_text(self, text):
        self.lbl.configure(text=text)

    def set_enabled(self, on):
        self.enabled = on
        self.lbl.configure(fg=self.fg if on else DIM,
                           cursor="hand2" if on else "arrow")
        self.configure(bg=self.bg)
        self.lbl.configure(bg=self.bg)


class FlatCheck(tk.Frame):
    """Checkbox built from labels so colors render on macOS too."""
    def __init__(self, parent, text, variable, bg, fg, font):
        super().__init__(parent, bg=bg)
        self.var = variable
        self.box = tk.Label(self, width=2, bg=bg, fg=ACCENT, font=font,
                            cursor="hand2")
        self.box.pack(side="left")
        self.txt = tk.Label(self, text=text, bg=bg, fg=fg, font=font,
                            cursor="hand2")
        self.txt.pack(side="left")
        for w in (self.box, self.txt):
            w.bind("<Button-1>", self._toggle)
        self._redraw()

    def _toggle(self, _e):
        self.var.set(not self.var.get())
        self._redraw()

    def _redraw(self):
        self.box.configure(text="[x]" if self.var.get() else "[ ]")


# ============================== console card ==================================
class ConsoleCard:
    """One slot, drawn as an Xbox console with an editable name + IP."""

    CW, CH = 150, 116   # canvas size

    def __init__(self, parent, index, fonts):
        self.index = index
        self.fonts = fonts
        self.state = "on"          # on | off | spin | host

        self.enabled = tk.BooleanVar(value=True)
        self.name_var = tk.StringVar(value=f"Xbox {index + 1}")
        self.ip_var = tk.StringVar(value="")
        self.mac_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")
        self.base_status = ""   # shown when enabled & not host (e.g. "detected")

        self.frame = tk.Frame(parent, bg=PANEL)
        self.canvas = tk.Canvas(self.frame, width=self.CW, height=self.CH,
                                bg=PANEL, highlightthickness=0, cursor="hand2")
        self.canvas.pack()
        self.canvas.bind("<Button-1>", lambda e: self.toggle())

        self.name_entry = tk.Entry(self.frame, textvariable=self.name_var,
                                   justify="center", bg="#0a120d", fg=TEXT,
                                   insertbackground=ACCENT, relief="flat",
                                   width=15, font=fonts["body"])
        self.name_entry.pack(pady=(3, 0))
        self.ip_entry = tk.Entry(self.frame, textvariable=self.ip_var,
                                 justify="center", bg=PANEL, fg=DIM,
                                 insertbackground=ACCENT, relief="flat",
                                 width=15, font=fonts["mono_s"])
        self.ip_entry.pack()
        self.status = tk.Label(self.frame, textvariable=self.status_var,
                               bg=PANEL, fg=ACCENT, font=fonts["small"])
        self.status.pack()

        self.draw()

    # ---- drawing ----
    def draw(self):
        c = self.canvas
        c.delete("all")
        W, H = self.CW, self.CH
        enabled = self.enabled.get()
        hl = self.state if self.state in ("spin", "host") else None

        if hl == "host":
            round_rect(c, 3, 3, W - 3, H - 3, 16, fill="", outline=WIN, width=4)
        elif hl == "spin":
            round_rect(c, 3, 3, W - 3, H - 3, 16, fill="", outline=ACCENT, width=3)

        # console body (the classic chunky black box)
        body = "#0d0d0d" if enabled else "#1a1a1a"
        round_rect(c, 16, 14, W - 16, H - 12, 13, fill=body, outline="#000000")
        round_rect(c, 22, 18, W - 22, 30, 7, fill="#1d1d1d", outline="")  # sheen

        # the green jewel + X logo
        cx, cy, R = W // 2, H // 2 - 1, 25
        outer = "#1f6f43" if enabled else "#27332d"
        inner = ACCENT if enabled else "#3c4f46"
        c.create_oval(cx - R, cy - R, cx + R, cy + R, fill=outer, outline="")
        c.create_oval(cx - R + 3, cy - R + 3, cx + R - 3, cy + R - 3,
                      fill=inner, outline="")
        c.create_oval(cx - R + 6, cy - R + 5, cx - 2, cy - 7,
                      fill="#bfffd9" if enabled else "#5a6b61", outline="")
        xcol = "#f4fff9" if enabled else "#828f88"
        c.create_line(cx - 11, cy - 11, cx + 11, cy + 11,
                      fill=xcol, width=7, capstyle="round")
        c.create_line(cx + 11, cy - 11, cx - 11, cy + 11,
                      fill=xcol, width=7, capstyle="round")

        # power LED
        led = "#2a2a2a"
        if hl == "host":
            led = WIN
        elif enabled:
            led = LED_ON
        ly = H - 20
        c.create_oval(cx - 5, ly - 5, cx + 5, ly + 5, fill=led, outline="")

        self.name_entry.configure(fg=TEXT if enabled else DIM)
        if self.state == "host":
            self.status_var.set("HOST")
            self.status.configure(fg=WIN)
        elif not enabled:
            self.status_var.set("off")
            self.status.configure(fg=DIM)
        else:
            self.status_var.set(self.base_status)
            self.status.configure(fg=ACCENT)

    # ---- behavior ----
    def toggle(self):
        self.enabled.set(not self.enabled.get())
        self.state = "on" if self.enabled.get() else "off"
        self.draw()

    def set_state(self, state):
        self.state = state
        self.draw()

    def reset_state(self):
        self.state = "on" if self.enabled.get() else "off"
        self.draw()

    def is_eligible(self):
        return self.enabled.get() and (
            self.name_var.get().strip() or self.ip_var.get().strip())

    def label(self):
        name = self.name_var.get().strip() or "Xbox"
        ip = self.ip_var.get().strip()
        return f"{name}  ({ip})" if ip else name


# ================================ app =========================================
class App:
    def __init__(self, root, selftest=False):
        self.root = root
        self.q = queue.Queue()
        self.spinning = False

        root.title("Halo System Link  -  Host Picker")
        root.configure(bg=BG)
        root.minsize(720, 660)

        self.fonts = {
            "title":  tkfont.Font(family="Helvetica", size=18, weight="bold"),
            "body":   tkfont.Font(family="Helvetica", size=10),
            "small":  tkfont.Font(family="Helvetica", size=8),
            "mono_s": tkfont.Font(family="Courier", size=9),
            "big":    tkfont.Font(family="Helvetica", size=20, weight="bold"),
        }

        self._build_header()
        self._build_grid()
        self._build_actions()
        self._build_banner()

        try:
            _, net = get_local_subnet()
            self.subnet_var.set(str(net))
        except Exception:
            self.subnet_var.set("192.168.1.0/24")

        if selftest:
            root.after(150, root.destroy)

    def _build_header(self):
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill="x", padx=18, pady=(14, 4))
        tk.Label(head, text="HALO SYSTEM LINK", bg=BG, fg=ACCENT,
                 font=self.fonts["title"]).pack(anchor="w")
        tk.Label(head, text="Random host picker  -  8 Xboxes  -  click a "
                            "console to toggle it", bg=BG, fg=DIM,
                 font=self.fonts["small"]).pack(anchor="w")

        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=18, pady=(2, 6))
        tk.Label(bar, text="Subnet:", bg=BG, fg=TEXT,
                 font=self.fonts["body"]).pack(side="left")
        self.subnet_var = tk.StringVar()
        tk.Entry(bar, textvariable=self.subnet_var, bg=PANEL, fg=TEXT,
                 insertbackground=ACCENT, relief="flat", width=18,
                 font=self.fonts["mono_s"]).pack(side="left", padx=8)

        self.xbox_only = tk.BooleanVar(value=True)
        FlatCheck(bar, "Xbox only", self.xbox_only, BG, TEXT,
                  self.fonts["small"]).pack(side="left", padx=6)

        self.scan_btn = FlatButton(bar, "Scan LAN", self.on_scan,
                                   bg=PANEL, fg=ACCENT, hover="#16271d",
                                   font=self.fonts["body"], padx=12, pady=4)
        self.scan_btn.pack(side="left", padx=6)
        self.scan_status = tk.Label(bar, text="", bg=BG, fg=DIM,
                                    font=self.fonts["small"])
        self.scan_status.pack(side="left", padx=8)

    def _build_grid(self):
        wrap = tk.Frame(self.root, bg=PANEL, highlightthickness=1,
                        highlightbackground="#1d3328")
        wrap.pack(fill="both", expand=True, padx=18, pady=6)
        grid = tk.Frame(wrap, bg=PANEL)
        grid.pack(padx=10, pady=10)
        self.cards = []
        for i in range(NUM_SLOTS):
            card = ConsoleCard(grid, i, self.fonts)
            card.frame.grid(row=i // COLUMNS, column=i % COLUMNS,
                            padx=8, pady=8)
            self.cards.append(card)

    def _build_actions(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=18, pady=(2, 2))
        self.pick_btn = FlatButton(bar, "PICK  HOST", self.on_pick,
                                   bg=ACCENT, fg=BG, hover=WIN,
                                   font=self.fonts["title"], padx=22, pady=7,
                                   border="#2c8f5e")
        self.pick_btn.pack(side="left")
        FlatButton(bar, "Enable all", lambda: self._set_all(True),
                   bg=PANEL, fg=TEXT, hover="#16271d",
                   font=self.fonts["small"], padx=10, pady=7
                   ).pack(side="left", padx=(10, 4))
        FlatButton(bar, "Disable all", lambda: self._set_all(False),
                   bg=PANEL, fg=TEXT, hover="#16271d",
                   font=self.fonts["small"], padx=10, pady=7
                   ).pack(side="left", padx=4)
        FlatButton(bar, "Randomize", self.on_randomize,
                   bg=PANEL, fg=ACCENT, hover="#16271d",
                   font=self.fonts["small"], padx=10, pady=7
                   ).pack(side="left", padx=4)
        FlatButton(bar, "Clear", self.on_clear,
                   bg=PANEL, fg=TEXT, hover="#16271d",
                   font=self.fonts["small"], padx=10, pady=7
                   ).pack(side="left", padx=4)

    def _build_banner(self):
        self.banner = tk.Frame(self.root, bg=PANEL, height=60)
        self.banner.pack(fill="x", padx=18, pady=(6, 14))
        self.banner.pack_propagate(False)
        self.result = tk.Label(self.banner, text="Pick a host to begin",
                               bg=PANEL, fg=DIM, font=self.fonts["big"])
        self.result.pack(expand=True)

    # ---- actions ----
    def _set_all(self, value):
        for card in self.cards:
            card.enabled.set(value)
            card.reset_state()

    def on_randomize(self):
        """Randomly choose which consoles are in the running (>=2 live)."""
        if self.spinning:
            return
        usable = [c for c in self.cards
                  if c.name_var.get().strip() or c.ip_var.get().strip()]
        pool = usable if len(usable) >= 2 else self.cards
        while True:
            picks = {c: (random.random() < 0.6) for c in pool}
            if sum(picks.values()) >= 2:
                break
        for card in self.cards:
            card.enabled.set(picks.get(card, False))
            card.reset_state()
        live = sum(1 for c in self.cards if c.enabled.get())
        self.result.configure(text=f"Randomized lineup  -  {live} in", fg=ACCENT)

    def on_clear(self):
        for i, card in enumerate(self.cards):
            card.name_var.set(f"Xbox {i + 1}")
            card.ip_var.set("")
            card.mac_var.set("")
            card.status_var.set("")
            card.base_status = ""
            card.enabled.set(True)
            card.reset_state()
        self.result.configure(text="Pick a host to begin", fg=DIM)

    def on_scan(self):
        if self.spinning:
            return
        try:
            net = ipaddress.ip_network(self.subnet_var.get().strip(),
                                       strict=False)
        except ValueError:
            self.scan_status.configure(text="bad subnet", fg="#ff7a7a")
            return
        self.scan_btn.set_enabled(False); self.scan_btn.set_text("Scanning...")
        self.scan_status.configure(text="scanning " + str(net), fg=DIM)
        threading.Thread(target=self._scan_worker, args=(net,),
                         daemon=True).start()
        self.root.after(100, self._poll_scan)

    def _scan_worker(self, net):
        try:
            hosts, note = discover(net)
            self.q.put(("ok", hosts, note))
        except Exception as e:
            self.q.put(("err", str(e), ""))

    def _poll_scan(self):
        try:
            kind, payload, note = self.q.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_scan)
            return
        self.scan_btn.set_enabled(True); self.scan_btn.set_text("Scan LAN")
        if kind == "err":
            self.scan_status.configure(text="error: " + payload, fg="#ff7a7a")
            return
        hosts = payload
        if self.xbox_only.get():
            hosts = [(ip, mac) for ip, mac in hosts if is_xbox(mac)]
        self._fill(hosts)
        msg = f"found {len(hosts)} console(s)"
        if note:
            msg += "  -  " + note
        self.scan_status.configure(text=msg, fg=ACCENT if hosts else DIM)

    def _fill(self, hosts):
        for card in self.cards:
            card.ip_var.set("")
            card.mac_var.set("")
            card.status_var.set("")
            card.base_status = ""
            card.enabled.set(False)
            card.reset_state()
        for i, (ip, mac) in enumerate(hosts[:NUM_SLOTS]):
            card = self.cards[i]
            card.ip_var.set(ip)
            card.mac_var.set(mac)
            card.enabled.set(True)
            hn = hostname_for(ip)
            if hn:
                card.name_var.set(hn)
            elif not card.name_var.get().strip():
                card.name_var.set(f"Xbox {i + 1}")
            card.base_status = "detected"
            card.reset_state()
        if len(hosts) > NUM_SLOTS:
            self.cards[-1].base_status = f"+{len(hosts) - NUM_SLOTS} more"
            self.cards[-1].reset_state()

    def on_pick(self):
        if self.spinning:
            return
        eligible = [c for c in self.cards if c.is_eligible()]
        if not eligible:
            self.result.configure(text="No eligible Xboxes", fg="#ff7a7a")
            return
        for c in self.cards:
            c.reset_state()
        self.result.configure(text="Spinning...", fg=TEXT)
        winner = random.choice(eligible)
        total = 18 + random.randint(0, len(eligible) * 2)
        self._spin(eligible, winner, 0, total)

    def _spin(self, eligible, winner, step, total):
        self.spinning = True
        self.pick_btn.set_enabled(False)
        for c in eligible:
            if c.state == "spin":
                c.set_state("on")
        if step < total:
            eligible[step % len(eligible)].set_state("spin")
            delay = int(40 + (step / max(total, 1)) ** 2 * 230)  # ease-out
            self.root.after(delay, self._spin, eligible, winner, step + 1, total)
        else:
            winner.set_state("host")
            self.result.configure(text="HOST:  " + winner.label(), fg=WIN)
            self.spinning = False
            self.pick_btn.set_enabled(True)


def main():
    selftest = "--selftest" in sys.argv
    root = tk.Tk()
    App(root, selftest=selftest)
    root.mainloop()


if __name__ == "__main__":
    main()
