# Psyche

**Psyche** is a minimalist terminal VPN client written in pure C for Linux, powered by **Xray-core** in TUN mode.

Built as a small project for myself only. There's zero GUI or ncurses dependencies. It provides full system-wide Layer 3 tunneling, DPI circumvention (packet fragmentation), and uTLS fingerprint cycling.

---

## Target Platform: Void Linux + iwd

Psyche is designed specifically for minimalistic Linux setups, running on:
* **Void Linux** (compatible with both `glibc` and `musl`)
* **`iwd`** (Intel Wireless Daemon) or standard Ethernet
* **`runit`** init system (no `systemd` or `systemd-resolved` dependencies)

### Why Void + iwd?
1. **Direct Kernel Routing:** Standard VPN clients rely on NetworkManager dispatcher scripts or `systemd-resolved` DBus APIs. Psyche discovers your physical gateway and network interface directly via `iproute2`, binding routing tables (`0.0.0.0/1` and `128.0.0.0/1`) cleanly without daemon bloat.
2. **Deterministic DNS Management:** Backs up `/etc/resolv.conf` on connect and restores it atomically on disconnect, avoiding conflicts with systemd service managers.
3. **Kernel Orphan Protection:** Spawns Xray with `PR_SET_PDEATHSIG`, ensuring child processes are automatically reaped by the Linux kernel if Psyche or your Wayland session abruptly exits.
4. **Dual-Stack Leak Suppression:** Temporarily shields IPv6 through `/proc/sys/net/ipv6/conf/all/disable_ipv6` during active tunnel links.

---

## Features

* **Supported Protocols:**
  * **VLESS** (with **XTLS-Vision**, **Reality**, uTLS profiles, WebSocket, gRPC)
  * **VMess** (Base64 JSON format)
  * **Trojan** (TLS)
  * **Shadowsocks**
* **DPI Evasion (hello cheburnet):**
  * Slices the TLS ClientHello into TCP micro-chunks (packets: tlshello, length: 10-20) so TSPU buffers can't extract the SNI domain, bypassing blocks and throttling (YouTube, Discord, etc.) on domestic ISPs.
  * Automatically parses and applies fragmentation settings straight from subscription links into Xray dialerProxy rules.
* **Network & Fingerprint Protection:**
  * **uTLS Fingerprint Cycling:** Press `f` to cycle between `chrome`, `randomized`, `firefox`, `safari`, and `ios` with live tunnel relinking.
  * **IPv6 Kill-Switch:** Eliminates dual-stack leaks when connected to IPv6-enabled wireless routers.
  * **Local Proxies:** Exposes auxiliary local **SOCKS5** (`127.0.0.1:10808`) and **HTTP** (`127.0.0.1:10809`) endpoints alongside TUN.
* **Terminal Native:**
  * No `ncurses` — communicates directly over raw VT100/ANSI sequences via `termios`.
  * Preserves terminal emulator background color, transparency, and Wayland blur.
  * Full UTF-8 support with East Asian and emoji-flag character width handling.

---

## Installation on Void Linux

### 1. Install Dependencies
```sh
# Install base toolchain, curl, and iproute2
xbps-install -S gcc make curl iproute2

# Install Xray-core (download official release binary)
curl -Lo /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
sudo unzip -j /tmp/xray.zip xray -d /usr/local/bin/
sudo chmod +x /usr/local/bin/xray
```

### 2. Build Psyche

```sh
git clone https://github.com/6hYsteria9/psyche.git
cd psyche

# Optional: edit config.mk for paths or config.def.h for defaults
make
sudo make install
```
Binaries install to `/usr/local/bin/psyche` and man pages install to `/usr/local/share/man/man1/psyche.1`.

---

## Usage

Because Psyche configures network interfaces and routing tables, it requires root permissions (`sudo` or `doas`):

```sh
# First run (prompts for subscription URL if not configured):
sudo psyche

# Or pass a subscription link explicitly:
sudo psyche -u "https://example.com/subscription"

# Or load from a local file:
sudo psyche -f /path/to/links.txt
```

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
| `/` | Search / filter nodes by name or address (`Esc` to clear) |
| `s` | Enter / edit subscription URL |
| `u` | Update nodes from configured subscription URL |
| `q` | Clean shutdown (restores routes, DNS, and IPv6) |

---

## Configuration

Custom compile-time options are configured in `config.h` (copied from `config.def.h` on first build):

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

## Repository Structure

```text
psyche/
├── .gitignore        # Build & artifact exclusions
├── config.def.h      # Compile-time default configurations
├── config.mk         # Toolchain and installation paths
├── LICENSE           # Permissive ISC license
├── Makefile          # Clean build & package script
├── psyche.1          # Unix troff/groff manual page
├── README.md         # Documentation
└── src/
    ├── cJSON.c / .h       # Lightweight JSON parser
    ├── main.c             # Entry point, signals, config persistence
    ├── ping.c / .h        # Non-blocking TCP ping engine
    ├── sub_parser.c / .h  # Subscription link & fragment parser
    ├── tui.c / .h         # Minimalist ANSI terminal TUI
    ├── tun_mgr.c / .h     # Routing, kernel signal hooks, IPv6 shielding
    └── xray_config.c / .h # Xray routing and JSON stream generator
```

---

## License

ISC License. See [`LICENSE`](LICENSE) for details.


