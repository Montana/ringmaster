# Halo System Link: Host Picker

Randomly pick which Xbox should host a Halo **System Link** match. Built for the LAN era of **Halo 2** (original Xbox) and **Halo 3** (Xbox 360), where the
"host" is simply whichever console *creates* the game while the others join. This tool can't force a particular console to host, but it fairly settles the
question of *who should* — find the consoles on your network (or type them in) and let it spin for a random pick.

https://github.com/user-attachments/assets/1fca5176-fbe8-4e8a-b52e-bdea9a516dfe

There are two programs in this project:

| File | What it is |
| --- | --- |
| `xbox_host_picker_gui.py` | Desktop GUI — eight consoles drawn as Xboxes, with a roulette-style spin. The main app. |
| `xbox_host_picker.py` | Command-line version — same detection, text output. Good for scripts or no-GUI machines. |

---

## Features

- **Eight Xbox slots**, each drawn as a console with the green jewel logo and a
  power LED. Click a console to toggle it in or out of the running.
- **LAN scan** that auto-fills the slots with consoles it finds, using their
  reverse-DNS name where available.
- **"Xbox only" filter** that flags devices by their Microsoft MAC prefix.
- **Pick Host** — a roulette spin flashes through the eligible consoles, eases
  out, and lands on a random winner (gold ring + `HOST` tag).
- **Randomize** — randomly choose which consoles are in the running (always
  keeps at least two live), for randomly benching players between rounds.
- **Manual mode** — ignore scanning entirely and just type eight names in.
- Cross-platform UI (Windows / macOS / Linux) with no theming surprises.

---

## Requirements

- **Python 3.8+**
- **Tkinter** — bundled with Python on Windows and macOS. On some Linux distros
  it's a separate package:
  ```bash
  sudo apt-get install python3-tk      # Debian / Ubuntu
  sudo dnf install python3-tkinter     # Fedora
  ```
- **scapy** *(optional, recommended)* — gives the most reliable network scan.
  Without it, the tool falls back to a ping sweep automatically.
  ```bash
  pip install scapy
  ```

---

## Quick start (GUI)

```bash
python xbox_host_picker_gui.py
```

1. Power on your consoles and connect them to the same switch / LAN.
2. Click **Scan LAN** to auto-fill the slots — or just type a name (and
   optionally an IP) under each Xbox.
3. Toggle consoles on/off by clicking them, or use **Enable all** /
   **Disable all** / **Randomize**.
4. Hit **PICK HOST**. The winner lights up gold and shows in the banner.

> Tip: original Xboxes sometimes only appear on the network once a System Link
> game is loaded, so boot into Halo 2's System Link lobby before scanning if a
> console doesn't show up.

---

## Quick start (CLI)

```bash
python xbox_host_picker.py            # scan, then pick a random host
python xbox_host_picker.py --list     # scan and just list the consoles
```

### Options

| Flag | Effect |
| --- | --- |
| `--subnet 192.168.1.0/24` | CIDR to scan (default: auto-detect your /24). |
| `--list` | List detected consoles without picking. |
| `--all` | Treat every live host as eligible, not just Xboxes. |
| `--add 192.168.1.50` | Force-include an IP (repeatable). |
| `--exclude 192.168.1.50` | Exclude an IP from the pick (repeatable). |
| `--ping-only` | Skip scapy and use the ping-sweep method. |
| `--seed 7` | Reproducible pick (useful for tournament brackets). |

Example:

```bash
python xbox_host_picker.py --add 192.168.1.50 --add 192.168.1.51 --seed 7
```

---

## How detection works

1. **Find live hosts.** With scapy installed, the tool sends an ARP sweep across
   the subnet (most reliable; needs `sudo` on Linux/macOS). Otherwise it pings
   every address in the subnet and then reads your system ARP table.
2. **Identify Xboxes.** Each host's MAC address is checked against a list of
   Microsoft OUI prefixes (the first three octets of the MAC). Matches get
   flagged as consoles.
3. **Pick.** A random eligible console is chosen.

### What this means in practice

- Auto-scan finds devices that **have an IP address on the subnet you scan** —
  i.e. consoles on a normal LAN with a router/DHCP. If you're running pure
  System Link over a dumb, router-less switch, a console may never get an IP and
  won't appear; in that case, type it in manually.
- The Xbox MAC list is **best-effort**. Original Xboxes shipped with several
  network-chip vendors over the years, and some third-party adapters don't carry
  a Microsoft prefix, so a real console may not get auto-flagged. Use the escape
  hatches below.

---

## Configuration

Open either file and edit the constants near the top.

- **`NUM_SLOTS`** / **`COLUMNS`** (GUI) — change the number of consoles or the
  grid shape.
- **`XBOX_OUIS`** — the set of Microsoft/Xbox MAC prefixes. If a console isn't
  being flagged, scan with **"Xbox only" unticked** (GUI) or `--all` (CLI),
  read the MAC it reports, and add that prefix here. Prefixes are uppercase,
  colon-separated, e.g. `"00:22:48"`. You can verify a prefix against the
  [IEEE OUI registry](https://standards-oui.ieee.org/).

---

## Troubleshooting

**No consoles found.**
Make sure the consoles are powered on and on the same LAN. Try **"Xbox only"
unticked** / `--all` to see every live host, then add the right IPs or MAC
prefixes. Remember an OG Xbox may need a System Link game loaded first.

**Scan says "scapy needs root".**
Run with elevated privileges (`sudo python …` on Linux/macOS) or just let it use
the ping-sweep fallback — it works without root, just a little less reliably.

**A real Xbox isn't getting the green flag.**
Its MAC prefix probably isn't in `XBOX_OUIS`. Add it (see Configuration). The
console is still eligible if you enable its slot regardless of the flag.

**Buttons or text look unreadable.**
This was a macOS-specific issue with native Tk buttons and is fixed in the
current version (buttons are now custom-drawn). If you still see something off,
grab a screenshot — rendering differs across platforms.

---
Author
---
Michael Allen Mendy
