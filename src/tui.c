#define _GNU_SOURCE
#include "tui.h"
#include "ping.h"

#if defined(__has_include) && __has_include("config.h")
#include "config.h"
#else
#include "../config.def.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <sys/select.h>

static struct termios orig_termios;
static bool raw_mode_active = false;

// Dynamic string buffer for flicker-free rendering
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} abuf_t;

static void abuf_init(abuf_t *ab) {
    ab->cap = 8192;
    ab->len = 0;
    ab->buf = (char *)malloc(ab->cap);
    if (ab->buf) ab->buf[0] = '\0';
}

static void abuf_append(abuf_t *ab, const char *s, size_t len) {
    if (!ab->buf) return;
    if (ab->len + len + 1 >= ab->cap) {
        while (ab->len + len + 1 >= ab->cap) ab->cap *= 2;
        char *new_buf = (char *)realloc(ab->buf, ab->cap);
        if (!new_buf) return;
        ab->buf = new_buf;
    }
    memcpy(ab->buf + ab->len, s, len);
    ab->len += len;
    ab->buf[ab->len] = '\0';
}

static void abuf_appends(abuf_t *ab, const char *s) {
    abuf_append(ab, s, strlen(s));
}

static void abuf_free(abuf_t *ab) {
    if (ab->buf) free(ab->buf);
    ab->buf = NULL;
    ab->len = 0;
    ab->cap = 0;
}

static int utf8_char_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

static int utf8_char_width(const char *s, int *bytes_consumed) {
    unsigned char c = (unsigned char)*s;
    if (c < 0x80) {
        *bytes_consumed = 1;
        return 1;
    }
    int len = utf8_char_len(c);
    *bytes_consumed = len;

    if (len == 4) return 2; // Emojis, flags
    if (len == 3) {
        unsigned char c2 = (unsigned char)s[1];
        if (c == 0xE2 && c2 >= 0x80 && c2 <= 0xBF) return 1;
        return 2;
    }
    // 2-byte (Cyrillic, Greek, etc.)
    return 1;
}

static void safe_write(int fd, const void *buf, size_t count) {
    ssize_t ret = write(fd, buf, count);
    (void)ret;
}

/* Poll stdin with a short timeout (for distinguishing ESC from ESC-sequences) */
static bool stdin_has_data(int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

static void utf8_truncate_pad(char *dst, size_t dst_len, const char *src, int target_width) {
    int cur_width = 0;
    size_t d = 0;
    const char *s = src;
    while (*s && cur_width < target_width && d + 8 < dst_len) {
        int consumed = 1;
        int w = utf8_char_width(s, &consumed);
        if (cur_width + w > target_width) break;
        for (int i = 0; i < consumed; i++) {
            dst[d++] = *s++;
        }
        cur_width += w;
    }
    while (cur_width < target_width && d + 1 < dst_len) {
        dst[d++] = ' ';
        cur_width++;
    }
    dst[d] = '\0';
}

/* ── Terminal Theme Palette ──────────────────────────────────────────
 *
 *   Psyche strictly respects the terminal emulator's active theme
 *   (e.g. Everforest, Gruvbox, Catppuccin, Nord, Solarized, Tokyo Night):
 *
 *   - Normal text:      Default terminal foreground  \033[0m (never forced white)
 *   - Dim / secondary:  Faint / dim attribute        \033[2m (natural theme-dimmed fg)
 *   - Selected / bold:  Bold attribute               \033[1m
 *   - Semantic accents: Standard ANSI colors         \033[32m green, \033[33m yellow, \033[31m red, \033[36m cyan
 *   - Background:       Default terminal background  (preserves theme bg & transparency)
 *
 *   No hardcoded 24-bit RGB or assumed color 7 / color 8 (37m/90m) values.
 */

/* Minimal protocol label — keep it terse */
static const char *proto_short(protocol_t proto, security_t sec) {
    switch (proto) {
        case PROTO_VLESS:
            return sec == SEC_REALITY ? "vl+rl" :
                   sec == SEC_TLS     ? "vl+tl" : "vless";
        case PROTO_VMESS:      return "vmess";
        case PROTO_TROJAN:     return "trjan";
        case PROTO_SHADOWSOCKS:return "ss";
        default:               return "?";
    }
}

/* Simple hash for generating pseudo-random glitch chars per-node */
static unsigned int hash_str(const char *s) {
    unsigned int h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

/* Glitch alphabet — characters configured in config.def.h */
static const char *glitch_pool = glitch_chars;

void tui_raw_mode_disable(void) {
    if (raw_mode_active) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_mode_active = false;
        // Show cursor and switch from alternate buffer
        safe_write(STDOUT_FILENO, "\033[?25h\033[?1049l", 14);
    }
}

void tui_raw_mode_enable(void) {
    if (!raw_mode_active) {
        tcgetattr(STDIN_FILENO, &orig_termios);
        atexit(tui_raw_mode_disable);

        struct termios raw = orig_termios;
        raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        raw.c_oflag &= ~(OPOST);
        raw.c_cflag |= (CS8);
        raw.c_lflag &= ~(ECHO | ICANON | IEXTEN);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;

        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
        raw_mode_active = true;

        // Switch to alternate buffer and hide cursor
        safe_write(STDOUT_FILENO, "\033[?1049h\033[?25l", 14);
    }
}

void tui_init(tui_state_t *tui) {
    memset(tui, 0, sizeof(tui_state_t));
    tui_update_size(tui);
}

void tui_cleanup(void) {
    tui_raw_mode_disable();
}

void tui_update_size(tui_state_t *tui) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        tui->cols = ws.ws_col;
        tui->rows = ws.ws_row;
    } else {
        tui->cols = 80;
        tui->rows = 24;
    }
}

void tui_update_filter(tui_state_t *tui, const subscription_t *sub) {
    if (!sub) return;
    if (tui->filtered_indices) {
        free(tui->filtered_indices);
        tui->filtered_indices = NULL;
    }

    tui->filtered_indices = (int *)malloc(sub->count * sizeof(int));
    if (!tui->filtered_indices) {
        tui->filtered_count = 0;
        return;
    }

    size_t count = 0;
    for (size_t i = 0; i < sub->count; i++) {
        if (tui->search_query[0] == '\0') {
            tui->filtered_indices[count++] = (int)i;
        } else {
            // Case-insensitive substring match
            char query_lower[64];
            size_t ql = strlen(tui->search_query);
            for (size_t q = 0; q <= ql; q++) query_lower[q] = tolower((unsigned char)tui->search_query[q]);

            char name_lower[512];
            size_t nl = strlen(sub->nodes[i].name);
            for (size_t n = 0; n <= nl; n++) name_lower[n] = tolower((unsigned char)sub->nodes[i].name[n]);

            char addr_lower[256];
            size_t al = strlen(sub->nodes[i].address);
            for (size_t a = 0; a <= al; a++) addr_lower[a] = tolower((unsigned char)sub->nodes[i].address[a]);

            if (strstr(name_lower, query_lower) || strstr(addr_lower, query_lower)) {
                tui->filtered_indices[count++] = (int)i;
            }
        }
    }
    tui->filtered_count = count;

    if (tui->selected >= (int)tui->filtered_count) {
        tui->selected = tui->filtered_count > 0 ? (int)tui->filtered_count - 1 : 0;
    }
    if (tui->selected < 0) tui->selected = 0;
}

/* ── First-run setup ──────────────────────────────────────────────── */
/*    Shown once when no subscription URL is configured.               */
/*    Cold-boot terminal screen: sparse text, empty space.             */

static void first_run_render(tui_state_t *tui, const char *url, const char *status) {
    abuf_t ab;
    abuf_init(&ab);
    abuf_appends(&ab, "\033[H");  /* cursor home */

    int h = tui->rows;
    int pad = (h > 16) ? (h - 12) / 3 : 1;

    char tmp[2048];

    for (int i = 0; i < pad; i++)
        abuf_appends(&ab, "\033[K\r\n");

    /* brand */
    snprintf(tmp, sizeof(tmp), "  \033[1;32m%s\033[0m\033[K\r\n", brand_name);
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K\r\n");

    /* boot quote — dim terminal foreground */
    snprintf(tmp, sizeof(tmp), "  \033[2m%s\033[0m\033[K\r\n", boot_phrase);
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K\r\n");

    /* prompt — default terminal foreground */
    snprintf(tmp, sizeof(tmp), "  %s\033[K\r\n", boot_prompt);
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K\r\n");

    /* input line — green prompt, bold default fg for input, dim underscore */
    snprintf(tmp, sizeof(tmp),
             "  \033[32m>\033[0m \033[1m%s\033[0m\033[2m_\033[0m\033[K\r\n", url);
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K\r\n");

    /* status message (theme yellow) or blank */
    if (status[0]) {
        snprintf(tmp, sizeof(tmp), "  \033[33m%s\033[0m\033[K\r\n", status);
        abuf_appends(&ab, tmp);
    } else {
        abuf_appends(&ab, "\033[K\r\n");
    }
    abuf_appends(&ab, "\033[K\r\n");

    /* footer — dim key names, default text */
    abuf_appends(&ab,
        "  \033[2menter\033[0m confirm   "
        "\033[2mesc\033[0m quit\033[K");

    abuf_appends(&ab, "\033[J");  /* clear below */

    safe_write(STDOUT_FILENO, ab.buf, ab.len);
    abuf_free(&ab);
}

bool tui_first_run(tui_state_t *tui, subscription_t *sub) {
    tui_raw_mode_enable();

    char url[1024] = {0};
    char status[256] = {0};

    for (;;) {
        tui_update_size(tui);
        first_run_render(tui, url, status);

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) continue;

        status[0] = '\0';

        if (c == 27) {  /* Escape */
            if (stdin_has_data(50)) {
                /* Part of an escape sequence (arrow key, etc.) — drain and ignore */
                char discard;
                while (stdin_has_data(20))
                    read(STDIN_FILENO, &discard, 1);
            } else {
                /* Standalone Escape — quit */
                return false;
            }
        } else if (c == '\r' || c == '\n') {
            if (url[0] != '\0') {
                snprintf(status, sizeof(status), "fetching...");
                first_run_render(tui, url, status);

                int count = sub_fetch_url(sub, url);
                if (count > 0) {
                    snprintf(sub->url, sizeof(sub->url), "%s", url);
                    return true;
                } else {
                    snprintf(status, sizeof(status), "fetch failed. check url and retry.");
                }
            }
        } else if (c == 127 || c == 8) {  /* Backspace */
            size_t l = strlen(url);
            if (l > 0) url[l - 1] = '\0';
        } else if (c == 21) {  /* Ctrl-U — clear line */
            url[0] = '\0';
        } else if (c == 23) {  /* Ctrl-W — delete word */
            size_t l = strlen(url);
            while (l > 0 && url[l - 1] == ' ') l--;
            while (l > 0 && url[l - 1] != ' ' && url[l - 1] != '/') l--;
            url[l] = '\0';
        } else if (c >= 32 && c < 127) {  /* Printable ASCII */
            size_t l = strlen(url);
            if (l + 1 < sizeof(url)) {
                url[l] = c;
                url[l + 1] = '\0';
            }
        }
    }
}

/* ── Render ───────────────────────────────────────────────────────── */

void tui_render(tui_state_t *tui, const subscription_t *sub, const tun_manager_t *tun) {
    tui_update_size(tui);

    abuf_t ab;
    abuf_init(&ab);

    abuf_appends(&ab, "\033[H");  // cursor home

    int w = tui->cols;
    int h = tui->rows;
    if (w < 40) w = 40;
    if (h < 10) h = 10;

    char tmp[2048];
    time_t now = time(NULL);
    (void)now;

    /* ── Row 1:  brand + connection state ─────────────────────────── */
    /*    Left-aligned, sparse. Respects terminal theme palette.        */

    if (tun->status == TUN_STATUS_CONNECTED) {
        snprintf(tmp, sizeof(tmp),
                 " \033[1;32mpsyche\033[0m\033[2m/\033[32mlink\033[0m "
                 "\033[2m──\033[0m \033[1m%s\033[0m \033[2m->\033[0m \033[36m%s\033[0m",
                 tun->connected_name, tun->server_ip);
    } else if (tun->status == TUN_STATUS_CONNECTING) {
        snprintf(tmp, sizeof(tmp),
                 " \033[1;32mpsyche\033[0m\033[2m/\033[33msync\033[0m "
                 "\033[2m──\033[0m %s",
                 tun->connected_name);
    } else if (tun->status == TUN_STATUS_ERROR) {
        snprintf(tmp, sizeof(tmp),
                 " \033[1;32mpsyche\033[0m\033[2m/\033[31mfault\033[0m "
                 "\033[2m──\033[0m \033[31m%s\033[0m",
                 tun->error_msg);
    } else {
        snprintf(tmp, sizeof(tmp),
                 " \033[1;32mpsyche\033[0m\033[2m/void\033[0m");
    }
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K\r\n");

    /* ── Row 2:  context line (search / url-input / node count) ─── */

    if (tui->in_search) {
        snprintf(tmp, sizeof(tmp),
                 " \033[2m/\033[0m\033[1m%s\033[0m\033[2m_\033[0m", tui->search_query);
    } else if (tui->in_input_url) {
        snprintf(tmp, sizeof(tmp),
                 " \033[2murl>\033[0m \033[1m%s\033[0m\033[2m_\033[0m", tui->input_url);
    } else {
        snprintf(tmp, sizeof(tmp),
                 " \033[2m%zu node%s   %s   fp:%s   socks:%d   http:%d\033[0m",
                 tui->filtered_count,
                 tui->filtered_count == 1 ? "" : "s",
                 tun->tun_dev,
                 tun->fingerprint,
                 tun->socks_port, tun->http_port);
    }
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K\r\n");

    /* ── Row 3:  blank spacer ──────────────────────────────────────── */
    abuf_appends(&ab, "\033[K\r\n");

    /* ── Node list ─────────────────────────────────────────────────── */
    /*    No column headers.  Each row:                                 */
    /*      [marker] name                        proto   latency        */
    /*    Selected row gets a theme green ">" and bold theme text.      */
    /*    Active (connected) row gets a theme green dot.                */

    int list_height = h - 5;  // 3 header rows + 1 spacer + 1 footer
    if (list_height < 3) list_height = 3;

    /* scroll adjustment */
    if (tui->selected < tui->scroll_top) {
        tui->scroll_top = tui->selected;
    }
    if (tui->selected >= tui->scroll_top + list_height) {
        tui->scroll_top = tui->selected - list_height + 1;
    }

    int name_w = w - 22;  // space for marker(3) + proto(6) + ping(8) + pad
    if (name_w < 12) name_w = 12;

    for (int r = 0; r < list_height; r++) {
        int idx = tui->scroll_top + r;
        if (idx < (int)tui->filtered_count) {
            int sub_idx = tui->filtered_indices[idx];
            const server_node_t *node = &sub->nodes[sub_idx];
            bool is_sel  = (idx == tui->selected);
            bool is_act  = (tun->status == TUN_STATUS_CONNECTED &&
                            strcmp(tun->connected_name, node->name) == 0);

            /* Marker column */
            const char *marker;
            if (is_act && is_sel)      marker = "\033[1;32m > \033[0m";
            else if (is_act)           marker = "\033[32m . \033[0m";
            else if (is_sel)           marker = "\033[1;32m > \033[0m";
            else                       marker = "   ";

            /* Name — truncate/pad */
            char pname[512];
            utf8_truncate_pad(pname, sizeof(pname), node->name, name_w);

            /* Ping string */
            char ping_s[16];
            if (node->ping_ms >= 0) {
                snprintf(ping_s, sizeof(ping_s), "%4dms", node->ping_ms);
            } else if (node->ping_ms == -2) {
                snprintf(ping_s, sizeof(ping_s), "  ----");
            } else {
                /* Unmeasured — fill with a subtle glitch char */
                unsigned int gh = hash_str(node->name);
                char gc = glitch_pool[gh % strlen(glitch_pool)];
                snprintf(ping_s, sizeof(ping_s), "     %c", gc);
            }

            const char *proto_s = proto_short(node->protocol, node->security);

            /* Colorize using terminal's native theme:
             * Default FG (\033[0m), Bold (\033[1m), Dim (\033[2m), Theme Green (\033[32m).
             * Never hardcode \033[37m (white) or \033[90m (gray) so Everforest,
             * Gruvbox, Nord, Catppuccin, etc. render in their exact palette. */
            const char *name_color;
            const char *meta_color;
            if (is_sel) {
                name_color = "\033[1m";      /* bold terminal foreground */
                meta_color = "\033[0m";      /* normal terminal foreground */
            } else if (is_act) {
                name_color = "\033[32m";     /* theme green */
                meta_color = "\033[2m";      /* dim foreground */
            } else {
                name_color = "\033[0m";      /* default terminal foreground */
                meta_color = "\033[2m";      /* dim foreground */
            }

            snprintf(tmp, sizeof(tmp),
                     "%s%s%s\033[0m  %s%-5s %s\033[0m",
                     marker,
                     name_color, pname,
                     meta_color, proto_s,
                     ping_s);
            abuf_appends(&ab, tmp);
        }
        abuf_appends(&ab, "\033[K\r\n");
    }

    /* ── Footer: status or key hints ──────────────────────────────── */
    if (tui->status_msg[0] != '\0') {
        snprintf(tmp, sizeof(tmp), " \033[33m%s\033[0m", tui->status_msg);
    } else {
        snprintf(tmp, sizeof(tmp),
                 " \033[2menter\033[0m connect  "
                 "\033[2md\033[0m stop  "
                 "\033[2mf\033[0m fp  "
                 "\033[2m/\033[0m find  "
                 "\033[2mp\033[0m ping  "
                 "\033[2ms\033[0m url  "
                 "\033[2mu\033[0m sync  "
                 "\033[2mq\033[0m quit");
    }
    abuf_appends(&ab, tmp);
    abuf_appends(&ab, "\033[K");

    /* Clear any remaining lines below */
    abuf_appends(&ab, "\033[J");

    safe_write(STDOUT_FILENO, ab.buf, ab.len);
    abuf_free(&ab);
}

/* ── Input handling (unchanged logic, same keybinds) ──────────────── */

bool tui_handle_input(tui_state_t *tui, subscription_t *sub, tun_manager_t *tun) {
    char c = 0;
    if (read(STDIN_FILENO, &c, 1) != 1) return true;

    // Reset temporary status message on key press
    tui->status_msg[0] = '\0';

    // --- Search Mode ---
    if (tui->in_search) {
        if (c == '\r' || c == '\n') {
            tui->in_search = false;
        } else if (c == 27) { // Escape
            tui->in_search = false;
            tui->search_query[0] = '\0';
            tui_update_filter(tui, sub);
        } else if (c == 127 || c == 8) { // Backspace
            size_t l = strlen(tui->search_query);
            if (l > 0) {
                tui->search_query[l - 1] = '\0';
                tui_update_filter(tui, sub);
            }
        } else if (isprint((unsigned char)c)) {
            size_t l = strlen(tui->search_query);
            if (l + 1 < sizeof(tui->search_query)) {
                tui->search_query[l] = c;
                tui->search_query[l + 1] = '\0';
                tui_update_filter(tui, sub);
            }
        }
        return true;
    }

    // --- Input Subscription URL Mode ---
    if (tui->in_input_url) {
        if (c == '\r' || c == '\n') {
            tui->in_input_url = false;
            if (tui->input_url[0] != '\0') {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "fetching...");
                tui_render(tui, sub, tun);
                int count = sub_fetch_url(sub, tui->input_url);
                if (count > 0) {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "loaded %d nodes", count);
                    tui_update_filter(tui, sub);
                } else {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "fetch failed");
                }
            }
        } else if (c == 27) { // Escape
            tui->in_input_url = false;
            tui->input_url[0] = '\0';
        } else if (c == 127 || c == 8) { // Backspace
            size_t l = strlen(tui->input_url);
            if (l > 0) {
                tui->input_url[l - 1] = '\0';
            }
        } else if (isprint((unsigned char)c)) {
            size_t l = strlen(tui->input_url);
            if (l + 1 < sizeof(tui->input_url)) {
                tui->input_url[l] = c;
                tui->input_url[l + 1] = '\0';
            }
        }
        return true;
    }

    // --- Normal Navigation & Commands ---
    if (c == 'q' || c == 'Q') {
        return false; // Quit
    }

    if (c == 27) { // Escape or arrow sequence
        char seq[3];
        if (read(STDIN_FILENO, &seq[0], 1) == 1 && read(STDIN_FILENO, &seq[1], 1) == 1) {
            if (seq[0] == '[') {
                if (seq[1] == 'A') { // Up
                    if (tui->selected > 0) tui->selected--;
                } else if (seq[1] == 'B') { // Down
                    if (tui->selected + 1 < (int)tui->filtered_count) tui->selected++;
                } else if (seq[1] == '5' && read(STDIN_FILENO, &seq[2], 1) == 1 && seq[2] == '~') { // PageUp
                    tui->selected -= 10;
                    if (tui->selected < 0) tui->selected = 0;
                } else if (seq[1] == '6' && read(STDIN_FILENO, &seq[2], 1) == 1 && seq[2] == '~') { // PageDown
                    tui->selected += 10;
                    if (tui->selected >= (int)tui->filtered_count) tui->selected = (int)tui->filtered_count - 1;
                    if (tui->selected < 0) tui->selected = 0;
                } else if (seq[1] == 'H') { // Home
                    tui->selected = 0;
                } else if (seq[1] == 'F') { // End
                    tui->selected = tui->filtered_count > 0 ? (int)tui->filtered_count - 1 : 0;
                }
            }
        } else {
            // Standalone Escape clears search query
            if (tui->search_query[0] != '\0') {
                tui->search_query[0] = '\0';
                tui_update_filter(tui, sub);
            }
        }
        return true;
    }

    if (c == 'k') {
        if (tui->selected > 0) tui->selected--;
    } else if (c == 'j') {
        if (tui->selected + 1 < (int)tui->filtered_count) tui->selected++;
    } else if (c == 'g') {
        tui->selected = 0;
    } else if (c == 'G') {
        tui->selected = tui->filtered_count > 0 ? (int)tui->filtered_count - 1 : 0;
    } else if (c == '/') {
        tui->in_search = true;
        tui->search_query[0] = '\0';
    } else if (c == 's') {
        tui->in_input_url = true;
        snprintf(tui->input_url, sizeof(tui->input_url), "%s", sub->url);
    } else if (c == 'u') {
        if (sub->url[0]) {
            snprintf(tui->status_msg, sizeof(tui->status_msg), "syncing...");
            tui_render(tui, sub, tun);
            int count = sub_fetch_url(sub, sub->url);
            if (count > 0) {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "synced: %d nodes", count);
                tui_update_filter(tui, sub);
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "sync failed");
            }
        } else {
            snprintf(tui->status_msg, sizeof(tui->status_msg), "no url set (s)");
        }
    } else if (c == 'd') {
        if (tun->status == TUN_STATUS_CONNECTED) {
            tun_mgr_disconnect(tun);
            snprintf(tui->status_msg, sizeof(tui->status_msg), "disconnected");
        }
    } else if (c == 'f' || c == 'F') {
        // Cycle uTLS fingerprint profiles
        int cur = 0;
        for (int i = 0; i < NUM_FINGERPRINTS; i++) {
            if (strcmp(tun->fingerprint, fingerprints[i]) == 0) {
                cur = i;
                break;
            }
        }
        int next = (cur + 1) % NUM_FINGERPRINTS;
        snprintf(tun->fingerprint, sizeof(tun->fingerprint), "%s", fingerprints[next]);

        if (tun->status == TUN_STATUS_CONNECTED) {
            const server_node_t *connected_node = NULL;
            for (size_t i = 0; i < sub->count; i++) {
                if (strcmp(sub->nodes[i].name, tun->connected_name) == 0) {
                    connected_node = &sub->nodes[i];
                    break;
                }
            }
            if (connected_node) {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "fp: %s (relinking...)", tun->fingerprint);
                tui_render(tui, sub, tun);
                if (tun_mgr_connect(tun, connected_node) == 0) {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "fp: %s (linked)", tun->fingerprint);
                } else {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "relink failed: %s", tun->error_msg);
                }
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "fp: %s", tun->fingerprint);
            }
        } else {
            snprintf(tui->status_msg, sizeof(tui->status_msg), "fp: %s", tun->fingerprint);
        }
    } else if (c == 'p') {
        // Ping selected node
        if (tui->filtered_count > 0 && tui->selected < (int)tui->filtered_count) {
            int sub_idx = tui->filtered_indices[tui->selected];
            server_node_t *node = &sub->nodes[sub_idx];
            snprintf(tui->status_msg, sizeof(tui->status_msg), "ping %s...", node->address);
            tui_render(tui, sub, tun);
            int ms = ping_test_node(node, 1500);
            if (ms >= 0) {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "%s  %dms", node->address, ms);
            } else if (ms == -2) {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "%s  timeout", node->address);
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "%s  error", node->address);
            }
        }
    } else if (c == '\r' || c == '\n') {
        // Connect / Disconnect selected node
        if (tui->filtered_count > 0 && tui->selected < (int)tui->filtered_count) {
            int sub_idx = tui->filtered_indices[tui->selected];
            server_node_t *node = &sub->nodes[sub_idx];

            if (tun->status == TUN_STATUS_CONNECTED && strcmp(tun->connected_name, node->name) == 0) {
                // Already connected to this node: toggle disconnect
                tun_mgr_disconnect(tun);
                snprintf(tui->status_msg, sizeof(tui->status_msg), "disconnected");
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "linking...");
                tui_render(tui, sub, tun);
                if (tun_mgr_connect(tun, node) == 0) {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "linked: %s", node->name);
                } else {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "fault: %s", tun->error_msg);
                }
            }
        }
    }

    return true;
}
