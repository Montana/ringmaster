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

# --- Theme --------------------------------------------------------------------
BG     = "#080c0a"
PANEL  = "#0d1610"
ACCENT = "#4cff9f"
DIM    = "#4a6655"
TEXT   = "#c8e8d8"
WIN    = "#ffd447"
LED_ON = "#39ff14"
SEP    = "#1e3528"


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
        self.box.configure(text="✓" if self.var.get() else "☐")


# ============================== console card ==================================
class ConsoleCard:
    """One slot, drawn as an OG Xbox console with an editable name + IP."""

    CW, CH = 152, 118

    def __init__(self, parent, index, fonts):
        self.index = index
        self.fonts = fonts
        self.state = "on"          # on | off | spin | host

        self.enabled = tk.BooleanVar(value=True)
        self.name_var = tk.StringVar(value=f"Xbox {index + 1}")
        self.ip_var = tk.StringVar(value="")
        self.mac_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")
        self.base_status = ""

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
        state = self.state

        # — selection glow ring ———————————————————————————
        if state == "host":
            round_rect(c, 2, 2, W-2, H-2, 14, fill="", outline=WIN, width=4)
        elif state == "spin":
            round_rect(c, 2, 2, W-2, H-2, 14, fill="", outline=ACCENT, width=3)

        # — main body —————————————————————————————————————
        body = "#0c0c0c" if enabled else "#161616"
        round_rect(c, 10, 5, W-10, H-5, 13, fill=body, outline="#050505", width=2)

        # top bevel (lighter strip for depth)
        round_rect(c, 14, 8, W-14, 24, 6,
                   fill="#1c1c1c" if enabled else "#181818", outline="")

        # bottom base strip
        round_rect(c, 16, H-22, W-16, H-8, 5,
                   fill="#131313" if enabled else "#191919", outline="")

        # — disc slot (top center-left) ——————————————————
        sc = "#060606" if enabled else "#0b0b0b"
        c.create_rectangle(24, 15, W-42, 19, fill=sc, outline="#252525")

        # eject button (right of slot)
        c.create_rectangle(W-40, 13, W-28, 21,
                           fill="#1c1c1c" if enabled else "#161616",
                           outline="#2d2d2d")
        c.create_rectangle(W-38, 15, W-30, 19, fill="#111", outline="")

        # — X jewel (center, shifted right to leave port room) —
        jx, jy, R = W // 2 + 14, H // 2 + 2, 22

        # concentric rings: border → dark green → mid green → jewel face
        c.create_oval(jx-R-1, jy-R-1, jx+R+1, jy+R+1, fill="#050505", outline="")
        c.create_oval(jx-R,   jy-R,   jx+R,   jy+R,
                      fill="#062b17" if enabled else "#0d1a12", outline="")
        c.create_oval(jx-R+4, jy-R+4, jx+R-4, jy+R-4,
                      fill="#0f6432" if enabled else "#162618", outline="")
        c.create_oval(jx-R+7, jy-R+7, jx+R-7, jy+R-7,
                      fill="#1ab050" if enabled else "#1d3626", outline="")

        # specular shine (top-left arc highlight)
        c.create_oval(jx-R+9, jy-R+8, jx-1, jy-4,
                      fill="#90ffc8" if enabled else "#253d30", outline="")

        # X logo arms
        arm, lw = 11, 6
        xc = "#ffffff" if enabled else "#384e42"
        c.create_line(jx-arm, jy-arm, jx+arm, jy+arm,
                      fill=xc, width=lw, capstyle="round")
        c.create_line(jx+arm, jy-arm, jx-arm, jy+arm,
                      fill=xc, width=lw, capstyle="round")

        # — controller ports (2×2 grid, left side) ————————
        pw, ph, pg = 15, 11, 5
        px0 = 13
        py0 = H // 2 - ph - pg // 2
        pc = "#080808" if enabled else "#0e0e0e"

        for i in range(4):
            row, col = divmod(i, 2)
            px = px0 + col * (pw + pg)
            py = py0 + row * (ph + pg)
            round_rect(c, px, py, px + pw, py + ph, 2,
                       fill=pc, outline="#222222")
            # connector ridge
            my = py + ph // 2
            c.create_line(px + 3, my, px + pw - 3, my,
                          fill="#181818", width=1)

        # — power button (centered below port block) ——————
        pb_x = px0 + pw + pg // 2   # between the two port columns
        pb_y = H - 14

        # outer button ring
        c.create_oval(pb_x-7, pb_y-7, pb_x+7, pb_y+7,
                      fill="#0e0e0e", outline="#1e1e1e")
        # glow halo + LED core
        if state == "host":
            c.create_oval(pb_x-5, pb_y-5, pb_x+5, pb_y+5, fill="#5a4000", outline="")
            c.create_oval(pb_x-3, pb_y-3, pb_x+3, pb_y+3, fill=WIN, outline="")
        elif enabled:
            c.create_oval(pb_x-5, pb_y-5, pb_x+5, pb_y+5, fill="#0e3e0e", outline="")
            c.create_oval(pb_x-3, pb_y-3, pb_x+3, pb_y+3, fill=LED_ON, outline="")
        else:
            c.create_oval(pb_x-3, pb_y-3, pb_x+3, pb_y+3, fill="#111", outline="")

        # — subtle "xbox" emboss on top bevel —————————————
        xl = "#272727" if enabled else "#1d1d1d"
        c.create_text(22, 16, text="xbox", fill=xl,
                      font=("Helvetica", 7, "bold"), anchor="w")

        # — entry / status styling ————————————————————————
        self.name_entry.configure(fg=TEXT if enabled else DIM)
        if state == "host":
            self.status_var.set("★  HOST  ★")
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
        root.minsize(730, 680)

        self.fonts = {
            "title":  tkfont.Font(family="Helvetica", size=18, weight="bold"),
            "body":   tkfont.Font(family="Helvetica", size=10),
            "small":  tkfont.Font(family="Helvetica", size=8),
            "mono_s": tkfont.Font(family="Courier", size=9),
            "big":    tkfont.Font(family="Helvetica", size=20, weight="bold"),
        }

        self._build_header()
        self._build_separator()
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
        tk.Label(head, text="Random host picker  ·  up to 8 Xboxes  ·  "
                            "click a console to toggle it on/off",
                 bg=BG, fg=DIM, font=self.fonts["small"]).pack(anchor="w")

        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=18, pady=(4, 6))
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

    def _build_separator(self):
        tk.Frame(self.root, bg=SEP, height=1).pack(fill="x", padx=0, pady=0)

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
        self.banner = tk.Frame(self.root, bg=PANEL, height=68)
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
        if self.spinning:
            return
        usable = [c for c in self.cards
                  if c.name_var.get().strip() or c.ip_var.get().strip()]
        pool = usable if len(usable) >= 2 else self.cards
        for _ in range(1000):
            picks = {c: (random.random() < 0.6) for c in pool}
            if sum(picks.values()) >= 2:
                break
        for card in self.cards:
            card.enabled.set(picks.get(card, False))
            card.reset_state()
        live = sum(1 for c in self.cards if c.enabled.get())
        self.result.configure(text=f"Randomized lineup  ·  {live} in", fg=ACCENT)

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
        self.scan_btn.set_enabled(False)
        self.scan_btn.set_text("Scanning...")
        self.scan_status.configure(text="scanning " + str(net), fg=DIM)
        threading.Thread(target=self._scan_worker, args=(net,),
                         daemon=True).start()
        self.root.after(100, self._poll_scan)

    def _scan_worker(self, net):
        try:
            hosts, note = discover(net)
            # Resolve hostnames off the main thread to avoid blocking the UI
            resolved = [(ip, mac, hostname_for(ip)) for ip, mac in hosts]
            self.q.put(("ok", resolved, note))
        except Exception as e:
            self.q.put(("err", str(e), ""))

    def _poll_scan(self):
        try:
            kind, payload, note = self.q.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_scan)
            return
        self.scan_btn.set_enabled(True)
        self.scan_btn.set_text("Scan LAN")
        if kind == "err":
            self.scan_status.configure(text="error: " + payload, fg="#ff7a7a")
            return
        hosts = payload  # [(ip, mac, hostname), ...]
        if self.xbox_only.get():
            hosts = [(ip, mac, hn) for ip, mac, hn in hosts if is_xbox(mac)]
        self._fill(hosts)
        msg = f"found {len(hosts)} console(s)"
        if note:
            msg += "  ·  " + note
        self.scan_status.configure(text=msg, fg=ACCENT if hosts else DIM)

    def _fill(self, hosts):
        for card in self.cards:
            card.ip_var.set("")
            card.mac_var.set("")
            card.status_var.set("")
            card.base_status = ""
            card.enabled.set(False)
            card.reset_state()
        for i, (ip, mac, hn) in enumerate(hosts[:NUM_SLOTS]):
            card = self.cards[i]
            card.ip_var.set(ip)
            card.mac_var.set(mac)
            card.enabled.set(True)
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

        # Build a randomized spin sequence (no consecutive repeats) that
        # lands on the pre-chosen winner as the final step.
        n = 20 + random.randint(0, len(eligible) * 3)
        sequence = []
        prev = None
        for _ in range(n - 1):
            choices = [c for c in eligible if c is not prev] or eligible
            nxt = random.choice(choices)
            sequence.append(nxt)
            prev = nxt
        sequence.append(winner)

        self._spin(eligible, sequence, winner, 0)

    def _spin(self, eligible, sequence, winner, step):
        self.spinning = True
        self.pick_btn.set_enabled(False)
        for c in eligible:
            if c.state == "spin":
                c.set_state("on")
        if step < len(sequence):
            sequence[step].set_state("spin")
            t = step / max(len(sequence) - 1, 1)
            delay = int(40 + t * t * 300)   # ease-out: 40 ms → 340 ms
            self.root.after(delay, self._spin, eligible, sequence, winner, step + 1)
        else:
            winner.set_state("host")
            self.result.configure(text=f"★  HOST:  {winner.label()}  ★", fg=WIN)
            self.spinning = False
            self.pick_btn.set_enabled(True)


def main():
    selftest = "--selftest" in sys.argv
    root = tk.Tk()
    App(root, selftest=selftest)
    root.mainloop()


if __name__ == "__main__":
    main()
