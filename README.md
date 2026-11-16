# Psyche

**Psyche** is an ultra-minimalist terminal VPN client written in pure C for Linux, powered by **Xray-core** in TUN mode.

Built strictly adhering to the suckless philosophy: zero desktop bloat, zero GUI, and zero external library dependencies (no `ncurses`, no `cJSON`, no `libnetlink`). It provides full system-wide Layer 3 tunneling, deep packet inspection (DPI) circumvention, and live uTLS fingerprint cycling inside a tiny standalone binary (< 48 KB).

---

## Universal Linux Architecture

Unlike mainstream VPN clients that hard-depend on NetworkManager dispatcher scripts, systemd D-Bus APIs, or Polkit desktop agents, Psyche interfaces directly with the standard **Linux Kernel**:

* **Runs on Any Distribution:** Completely agnostic of distribution layout. Works seamlessly on **Arch, Void, Debian, Ubuntu, Fedora, Alpine, Gentoo, openSUSE, NixOS**, etc.
* **Dual C Library Support:** Compiles cleanly with both **`glibc`** and **`musl`** with standard C99/POSIX conformance (ideal for Alpine or minimal embedded Linux setups).
* **Init System Agnostic:** Operates identically whether your system boots with **`systemd`**, **`runit`**, **`OpenRC`**, **`s6`**, **`dinit`**, or runs headless inside a bare SSH session.
* **Network Stack Agnostic:** Discovers active default gateways directly from kernel `/proc/net/route` and `rtnetlink`. Works regardless of whether your network is managed by **`NetworkManager`**, **`iwd`**, **`wpa_supplicant`**, **`systemd-networkd`**, or static Ethernet.
* **Direct Kernel Netlink (`rtnetlink`):** Configures Layer 3 TUN routes (`0.0.0.0/1` and `128.0.0.0/1`) and IP addresses via in-process Netlink socket calls (`AF_NETLINK`), eliminating the latency and overhead of spawning external helper processes.
* **Atomic Symlink-Aware DNS:** Resolves canonical `/etc/resolv.conf` targets and performs atomic same-filesystem `rename(2)` swaps, safely coexisting with systemd-resolved, openresolv, or static configs without breaking symlinks.
* **Kernel Orphan Protection:** Spawns Xray with `PR_SET_PDEATHSIG`, guaranteeing that the background routing engine is reaped immediately by the kernel if Psyche or your terminal abruptly terminates.
* **Dual-Stack Leak Suppression:** Temporarily shields IPv6 through `/proc/sys/net/ipv6/conf/all/disable_ipv6` during active links.

---

## Features

* **Supported Protocols:**
  * **VLESS** (with **XTLS-Vision**, **Reality**, uTLS profiles, WebSocket, gRPC)
  * **VMess** (Base64 JSON format)
  * **Trojan** (TLS)
  * **Shadowsocks**
* **DPI Circumvention (Bypass Throttling & Blocks):**
  * Slices the TLS ClientHello into TCP micro-chunks (packets: `tlshello`, length: `10-20`) so ISP DPI / TSPU middleboxes cannot extract the SNI domain, bypassing throttling and blocks on domestic connections.
  * Parses and applies fragmentation settings directly from subscription links into Xray `dialerProxy` rules.
* **Network & Fingerprint Protection:**
  * **uTLS Fingerprint Cycling:** Press `f` to cycle between `chrome`, `randomized`, `firefox`, `safari`, and `ios` with live tunnel relinking.
  * **IPv6 Kill-Switch:** Eliminates dual-stack leaks when connected to IPv6-enabled wireless routers.
  * **Local Inbounds:** Exposes auxiliary local **SOCKS5** (`127.0.0.1:10808`) and **HTTP** (`127.0.0.1:10809`) endpoints alongside TUN.
* **High-Performance Non-Blocking Ping Engine:**
  * Press `P` to probe all servers simultaneously via non-blocking sockets and `poll()` without DNS delays.
  * Press `o` to sort nodes by latency (lowest ping first, unmeasured second, timeouts last).
* **Terminal Native & Full UTF-8:**
  * No `ncurses` — communicates directly over raw VT100/ANSI sequences via `termios`.
  * Preserves terminal emulator background color, transparency, and Wayland blur.
  * Full multi-byte UTF-8 input, Cyrillic / Russian case-insensitive search (`utf8_strcasestr`), and multi-byte backspacing.
  * Correct character width calculation for East Asian scripts and emoji flag glyphs.

---

## Installation

The only external requirement is **[Xray-core](https://github.com/XTLS/Xray-core)**. Psyche itself compiles with standard C build tools (`gcc` or `clang` and `make`).

### 1. Install Build Tools & Xray

#### Universal (Any Linux Distro)
```sh
# 1. Install standard build tools (gcc, make, curl) using your package manager:
# Arch:          sudo pacman -S gcc make curl
# Debian/Ubuntu: sudo apt install build-essential curl
# Fedora:        sudo dnf install gcc make curl
# Void:          sudo xbps-install -S gcc make curl
# Alpine:        sudo apk add build-base curl

# 2. Download official Xray-core binary:
curl -Lo /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
sudo unzip -j /tmp/xray.zip xray -d /usr/local/bin/
sudo chmod +x /usr/local/bin/xray
rm -f /tmp/xray.zip
```

### 2. Build & Install Psyche

```sh
git clone https://github.com/6hYsteria9/psyche.git
cd psyche

# Optional: edit config.mk for paths or config.def.h for custom defaults
make
sudo make install
```

Binaries are installed to `/usr/local/bin/psyche` and man pages to `/usr/local/share/man/man1/psyche.1`.

---

## Usage

Psyche configures network interfaces and routing tables using direct Linux kernel Netlink (`rtnetlink`).

### Option A: Running with File Capabilities (Recommended)

Grant network administration capabilities to run Psyche completely unprivileged without `sudo`:

```sh
sudo setcap cap_net_admin,cap_net_bind_service+ep /usr/local/bin/psyche
psyche
```

### Option B: Running with sudo / doas

```sh
# First run (prompts for subscription URL if not configured):
sudo psyche

# Or pass a subscription link explicitly:
sudo psyche -u "https://example.com/subscription"

# Or load from a local file:
sudo psyche -f /path/to/links.txt
```

When invoked via `sudo`, Psyche automatically drops effective privileges to the real invoking user (`$SUDO_UID`), saving user configuration into `~/.config/psyche/` without root ownership conflicts.

---

## Keybindings

| Key | Action |
|---|---|
| `Enter` | **Connect** to selected node / **Disconnect** if already active |
| `d` | Disconnect active tunnel |
| `f` | **Cycle uTLS fingerprint** (`chrome`, `randomized`, `firefox`, `safari`, `ios`) |
| `j` / `k` or `↓` / `↑` | Navigate node list |
| `PageDown` / `PageUp` | Scroll 10 nodes |
| `g` / `G` | Jump to first / last node |
| `p` | Measure TCP ping latency to selected server |
| `P` | Measure TCP ping latency to all filtered servers in parallel |
| `o` | **Sort nodes by latency** (toggles lowest ping / highest ping / original) |
| `/` | Search / filter nodes by name or address (`Esc` to clear) |
| `s` | Enter / edit subscription URL |
| `u` | Update nodes from configured subscription URL |
| `q` | Clean shutdown (restores routes, DNS, and IPv6) |

---

## Configuration

Custom compile-time options are configured in `config.h` (copied automatically from `config.def.h` on first build, following the `dwm` tradition):

```c
/* Interface & Port defaults */
static const char default_tun_dev[]  = "psyche0";
static const int  default_socks_port = 10808;
static const int  default_http_port  = 10809;

/* TCP ping probe timeout in milliseconds */
static const int  ping_timeout_ms    = 1500;

/* Supported TLS/uTLS fingerprint profiles */
static const char *fingerprints[] = {
    "chrome", "randomized", "firefox", "safari", "ios"
};
```

---

## Repository Structure (dwm-style flat-file layout)

```text
psyche/
├── .gitignore        # Build & artifact exclusions
├── config.def.h      # Compile-time default configurations, timeouts, keys, paths
├── config.mk         # Toolchain and installation paths
├── LICENSE           # Permissive ISC license
├── main.c            # Entry point, signals, config persistence, privilege dropping
├── Makefile          # Clean suckless build script
├── ping.c / .h       # Non-blocking parallel TCP ping engine
├── psyche.1          # Unix troff/groff manual page
├── README.md         # Documentation
├── sub_parser.c / .h # Subscription link parser & lightweight tokenizers
├── tui.c / .h        # Minimalist ANSI terminal TUI & UTF-8 / Cyrillic search engine
├── tun_mgr.c / .h    # Direct kernel Netlink routing, atomic DNS, privilege management
└── xray_config.c / .h# Static Xray JSON template generator
```

---

## License

ISC License. See [`LICENSE`](LICENSE) for details.
