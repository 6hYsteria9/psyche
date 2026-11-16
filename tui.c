#define _GNU_SOURCE
#include "tui.h"
#include "ping.h"
#include "config.h"

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
#include <stdarg.h>
#include <errno.h>
#include <wctype.h>

static struct termios orig_termios;
static bool raw_mode_active = false;

/* Dynamic string buffer for flicker-free rendering */
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

static void abuf_printf(abuf_t *ab, const char *fmt, ...) {
    if (!ab->buf) return;
    va_list ap, ap_copy;
    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    int needed = vsnprintf(NULL, 0, fmt, ap_copy);
    va_end(ap_copy);
    if (needed > 0) {
        if (ab->len + (size_t)needed + 1 >= ab->cap) {
            while (ab->len + (size_t)needed + 1 >= ab->cap) ab->cap *= 2;
            char *new_buf = (char *)realloc(ab->buf, ab->cap);
            if (!new_buf) {
                va_end(ap);
                return;
            }
            ab->buf = new_buf;
        }
        vsnprintf(ab->buf + ab->len, ab->cap - ab->len, fmt, ap);
        ab->len += (size_t)needed;
    }
    va_end(ap);
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

    if (len == 4) return 2; /* Emojis, flags */
    if (len == 3) {
        unsigned char c2 = (unsigned char)s[1];
        if (c == 0xE2 && c2 >= 0x80 && c2 <= 0xBF) return 1;
        return 2;
    }
    return 1;
}

static unsigned int utf8_next_codepoint(const char **s) {
    const unsigned char *p = (const unsigned char *)*s;
    if (!*p) return 0;

    unsigned int cp = 0;
    int len = 1;

    if (*p < 0x80) {
        cp = *p;
        len = 1;
    } else if ((*p & 0xE0) == 0xC0) {
        cp = *p & 0x1F;
        len = 2;
    } else if ((*p & 0xF0) == 0xE0) {
        cp = *p & 0x0F;
        len = 3;
    } else if ((*p & 0xF8) == 0xF0) {
        cp = *p & 0x07;
        len = 4;
    } else {
        *s += 1;
        return *p;
    }

    p++;
    for (int i = 1; i < len; i++) {
        if ((*p & 0xC0) != 0x80) {
            *s += i;
            return cp;
        }
        cp = (cp << 6) | (*p & 0x3F);
        p++;
    }

    *s = (const char *)p;
    return cp;
}

static unsigned int utf8_tolower(unsigned int cp) {
    if (cp >= 'A' && cp <= 'Z') return cp + 0x20;
    if (cp >= 0x0410 && cp <= 0x042F) return cp + 0x20; /* Cyrillic А-Я -> а-я */
    if (cp >= 0x0400 && cp <= 0x040F) return cp + 0x50; /* Cyrillic Ё, Є, І, Ї, etc. */
    if (cp < 0x80) return cp;
    wint_t w = towlower((wint_t)cp);
    return (unsigned int)w;
}

const char *utf8_strcasestr(const char *haystack, const char *needle) {
    if (!needle || !*needle) return haystack;
    if (!haystack || !*haystack) return NULL;

    const char *h_start = haystack;
    while (*h_start) {
        const char *h = h_start;
        const char *n = needle;
        bool match = true;

        while (*n) {
            if (!*h) {
                match = false;
                break;
            }
            unsigned int cp_h = utf8_tolower(utf8_next_codepoint(&h));
            unsigned int cp_n = utf8_tolower(utf8_next_codepoint(&n));
            if (cp_h != cp_n) {
                match = false;
                break;
            }
        }

        if (match) {
            return h_start;
        }

        utf8_next_codepoint(&h_start);
    }
    return NULL;
}

static int read_utf8_char(char first_byte, char *out, size_t out_cap) {
    unsigned char u0 = (unsigned char)first_byte;
    if (u0 >= 32 && u0 < 127) {
        if (out_cap < 2) return 0;
        out[0] = first_byte;
        out[1] = '\0';
        return 1;
    }
    if (u0 >= 0xC2 && u0 <= 0xF4) {
        int need = utf8_char_len(u0);
        if ((size_t)need >= out_cap) return 0;
        out[0] = first_byte;
        int got = 1;
        while (got < need) {
            char next_b;
            if (read(STDIN_FILENO, &next_b, 1) == 1) {
                out[got++] = next_b;
            } else {
                break;
            }
        }
        out[got] = '\0';
        return got;
    }
    return 0;
}

static void utf8_backspace(char *buf) {
    size_t l = strlen(buf);
    if (l > 0) {
        do {
            l--;
        } while (l > 0 && ((unsigned char)buf[l] & 0xC0) == 0x80);
        buf[l] = '\0';
    }
}

static void safe_write(int fd, const void *buf, size_t count) {
    ssize_t ret = write(fd, buf, count);
    (void)ret;
}

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

static unsigned int hash_str(const char *s) {
    unsigned int h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

static const char *glitch_pool = glitch_chars;

void tui_raw_mode_disable(void) {
    if (raw_mode_active) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_mode_active = false;
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

static const subscription_t *g_sort_sub = NULL;

static int cmp_ping_asc(const void *a, const void *b) {
    int idx_a = *(const int *)a;
    int idx_b = *(const int *)b;
    const server_node_t *na = &g_sort_sub->nodes[idx_a];
    const server_node_t *nb = &g_sort_sub->nodes[idx_b];

    int pa = na->ping_ms;
    int pb = nb->ping_ms;

    int score_a = (pa >= 0) ? pa : (pa == -1 ? 999998 : 999999);
    int score_b = (pb >= 0) ? pb : (pb == -1 ? 999998 : 999999);

    if (score_a != score_b) {
        return score_a - score_b;
    }
    return strcmp(na->name, nb->name);
}

static int cmp_ping_desc(const void *a, const void *b) {
    return cmp_ping_asc(b, a);
}

void tui_update_filter(tui_state_t *tui, const subscription_t *sub) {
    if (!sub) return;
    if (tui->filtered_indices) {
        free(tui->filtered_indices);
        tui->filtered_indices = NULL;
    }

    if (sub->count == 0) {
        tui->filtered_count = 0;
        tui->selected = 0;
        return;
    }

    tui->filtered_indices = (int *)malloc(sub->count * sizeof(int));
    if (!tui->filtered_indices) {
        tui->filtered_count = 0;
        return;
    }

    size_t count = 0;
    for (size_t i = 0; i < sub->count; i++) {
        if (tui->search_query[0] == '\0' ||
            utf8_strcasestr(sub->nodes[i].name, tui->search_query) != NULL ||
            utf8_strcasestr(sub->nodes[i].address, tui->search_query) != NULL) {
            tui->filtered_indices[count++] = (int)i;
        }
    }
    tui->filtered_count = count;

    if (tui->sort_mode == SORT_PING_ASC && tui->filtered_count > 1) {
        g_sort_sub = sub;
        qsort(tui->filtered_indices, tui->filtered_count, sizeof(int), cmp_ping_asc);
    } else if (tui->sort_mode == SORT_PING_DESC && tui->filtered_count > 1) {
        g_sort_sub = sub;
        qsort(tui->filtered_indices, tui->filtered_count, sizeof(int), cmp_ping_desc);
    }

    if (tui->selected >= (int)tui->filtered_count) {
        tui->selected = tui->filtered_count > 0 ? (int)tui->filtered_count - 1 : 0;
    }
    if (tui->selected < 0) tui->selected = 0;
}

static void first_run_render(tui_state_t *tui, const char *url, const char *status) {
    abuf_t ab;
    abuf_init(&ab);
    abuf_appends(&ab, "\033[H");

    int h = tui->rows;
    int pad = (h > 16) ? (h - 12) / 3 : 1;

    for (int i = 0; i < pad; i++)
        abuf_appends(&ab, "\033[K\r\n");

    /* Brand, boot phrase, and prompt */
    abuf_printf(&ab, "  \033[1;32m%s\033[0m\033[K\r\n\033[K\r\n", brand_name);
    abuf_printf(&ab, "  \033[2m%s\033[0m\033[K\r\n\033[K\r\n", boot_phrase);
    abuf_printf(&ab, "  %s\033[K\r\n\033[K\r\n", boot_prompt);
    abuf_printf(&ab, "  \033[32m>\033[0m \033[1m%s\033[0m\033[2m_\033[0m\033[K\r\n\033[K\r\n", url);

    if (status[0]) {
        abuf_printf(&ab, "  \033[33m%s\033[0m\033[K\r\n\033[K\r\n", status);
    } else {
        abuf_appends(&ab, "\033[K\r\n\033[K\r\n");
    }

    abuf_appends(&ab,
        "  \033[2menter\033[0m confirm   "
        "\033[2mesc\033[0m quit\033[K\033[J");

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

        if (c == 27) {
            if (stdin_has_data(50)) {
                char discard;
                while (stdin_has_data(20))
                    read(STDIN_FILENO, &discard, 1);
            } else {
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
        } else if (c == 127 || c == 8) {
            utf8_backspace(url);
        } else if (c == 21) {
            url[0] = '\0';
        } else if (c == 23) {
            size_t l = strlen(url);
            while (l > 0 && url[l - 1] == ' ') l--;
            while (l > 0 && url[l - 1] != ' ' && url[l - 1] != '/') l--;
            url[l] = '\0';
        } else {
            char ubuf[8];
            int ulen = read_utf8_char(c, ubuf, sizeof(ubuf));
            if (ulen > 0) {
                size_t l = strlen(url);
                if (l + (size_t)ulen < sizeof(url)) {
                    memcpy(url + l, ubuf, (size_t)ulen);
                    url[l + ulen] = '\0';
                }
            }
        }
    }
}

void tui_render(tui_state_t *tui, const subscription_t *sub, const tun_manager_t *tun) {
    tui_update_size(tui);

    abuf_t ab;
    abuf_init(&ab);
    abuf_appends(&ab, "\033[H");

    int w = tui->cols;
    int h = tui->rows;
    if (w < 40) w = 40;
    if (h < 10) h = 10;

    /* Row 1: Brand & status */
    if (tun->status == TUN_STATUS_CONNECTED) {
        abuf_printf(&ab,
                 " \033[1;32m%s\033[0m\033[2m/\033[32mlink\033[0m "
                 "\033[2m──\033[0m \033[1m%s\033[0m \033[2m->\033[0m \033[36m%s\033[0m\033[K\r\n",
                 brand_name, tun->connected_name, tun->server_ip);
    } else if (tun->status == TUN_STATUS_CONNECTING) {
        abuf_printf(&ab,
                 " \033[1;32m%s\033[0m\033[2m/\033[33msync\033[0m "
                 "\033[2m──\033[0m %s\033[K\r\n",
                 brand_name, tun->connected_name);
    } else if (tun->status == TUN_STATUS_ERROR) {
        abuf_printf(&ab,
                 " \033[1;32m%s\033[0m\033[2m/\033[31mfault\033[0m "
                 "\033[2m──\033[0m \033[31m%s\033[0m\033[K\r\n",
                 brand_name, tun->error_msg);
    } else {
        abuf_printf(&ab, " \033[1;32m%s\033[0m\033[2m/void\033[0m\033[K\r\n", brand_name);
    }

    /* Row 2: Context line */
    if (tui->in_search) {
        abuf_printf(&ab, " \033[2m/\033[0m\033[1m%s\033[0m\033[2m_\033[0m\033[K\r\n", tui->search_query);
    } else if (tui->in_input_url) {
        abuf_printf(&ab, " \033[2murl>\033[0m \033[1m%s\033[0m\033[2m_\033[0m\033[K\r\n", tui->input_url);
    } else {
        abuf_printf(&ab,
                 " \033[2m%zu node%s   %s   fp:%s   socks:%d   http:%d\033[0m\033[K\r\n",
                 tui->filtered_count,
                 tui->filtered_count == 1 ? "" : "s",
                 tun->tun_dev,
                 tun->fingerprint,
                 tun->socks_port, tun->http_port);
    }

    /* Row 3: Spacer */
    abuf_appends(&ab, "\033[K\r\n");

    /* Node list */
    int list_height = h - 5;
    if (list_height < 3) list_height = 3;

    if (tui->selected < tui->scroll_top) {
        tui->scroll_top = tui->selected;
    }
    if (tui->selected >= tui->scroll_top + list_height) {
        tui->scroll_top = tui->selected - list_height + 1;
    }

    int name_w = w - 22;
    if (name_w < 12) name_w = 12;

    for (int r = 0; r < list_height; r++) {
        int idx = tui->scroll_top + r;
        if (idx < (int)tui->filtered_count) {
            int sub_idx = tui->filtered_indices[idx];
            const server_node_t *node = &sub->nodes[sub_idx];
            bool is_sel  = (idx == tui->selected);
            bool is_act  = (tun->status == TUN_STATUS_CONNECTED &&
                            strcmp(tun->connected_name, node->name) == 0);

            const char *marker;
            if (is_act && is_sel)      marker = "\033[1;32m > \033[0m";
            else if (is_act)           marker = "\033[32m . \033[0m";
            else if (is_sel)           marker = "\033[1;32m > \033[0m";
            else                       marker = "   ";

            char pname[512];
            utf8_truncate_pad(pname, sizeof(pname), node->name, name_w);

            char ping_s[16];
            if (node->ping_ms >= 0) {
                snprintf(ping_s, sizeof(ping_s), "%4dms", node->ping_ms);
            } else if (node->ping_ms == -2) {
                snprintf(ping_s, sizeof(ping_s), "  ----");
            } else {
                unsigned int gh = hash_str(node->name);
                char gc = glitch_pool[gh % strlen(glitch_pool)];
                snprintf(ping_s, sizeof(ping_s), "     %c", gc);
            }

            const char *proto_s = proto_short(node->protocol, node->security);

            const char *name_color;
            const char *meta_color;
            if (is_sel) {
                name_color = "\033[1m";
                meta_color = "\033[0m";
            } else if (is_act) {
                name_color = "\033[32m";
                meta_color = "\033[2m";
            } else {
                name_color = "\033[0m";
                meta_color = "\033[2m";
            }

            abuf_printf(&ab,
                     "%s%s%s\033[0m  %s%-5s %s\033[0m\033[K\r\n",
                     marker,
                     name_color, pname,
                     meta_color, proto_s,
                     ping_s);
        } else {
            abuf_appends(&ab, "\033[K\r\n");
        }
    }

    /* Footer: Status or key hints */
    if (tui->status_msg[0] != '\0') {
        abuf_printf(&ab, " \033[33m%s\033[0m\033[K\033[J", tui->status_msg);
    } else {
        abuf_printf(&ab,
                 " \033[2menter\033[0m connect  "
                 "\033[2m%c\033[0m stop  "
                 "\033[2m%c\033[0m fp  "
                 "\033[2m%c\033[0m find  "
                 "\033[2m%c\033[0m sort  "
                 "\033[2m%c\033[0m ping  "
                 "\033[2m%c\033[0m all  "
                 "\033[2m%c\033[0m url  "
                 "\033[2m%c\033[0m sync  "
                 "\033[2m%c\033[0m quit\033[K\033[J",
                 key_disconnect, key_fingerprint, key_search, key_sort,
                 key_ping, key_ping_all, key_url, key_sync, key_quit);
    }

    safe_write(STDOUT_FILENO, ab.buf, ab.len);
    abuf_free(&ab);
}

bool tui_handle_input(tui_state_t *tui, subscription_t *sub, tun_manager_t *tun) {
    char c = 0;
    ssize_t n = read(STDIN_FILENO, &c, 1);
    if (n <= 0) return true;

    tui->status_msg[0] = '\0';

    /* --- Search Mode --- */
    if (tui->in_search) {
        if (c == '\r' || c == '\n') {
            tui->in_search = false;
        } else if (c == 27) {
            tui->in_search = false;
            tui->search_query[0] = '\0';
            tui_update_filter(tui, sub);
        } else if (c == 127 || c == 8) {
            utf8_backspace(tui->search_query);
            tui_update_filter(tui, sub);
        } else if (c == 21) {
            tui->search_query[0] = '\0';
            tui_update_filter(tui, sub);
        } else if (c == 23) {
            size_t l = strlen(tui->search_query);
            while (l > 0 && tui->search_query[l - 1] == ' ') l--;
            while (l > 0 && tui->search_query[l - 1] != ' ' && tui->search_query[l - 1] != '/') l--;
            tui->search_query[l] = '\0';
            tui_update_filter(tui, sub);
        } else {
            char ubuf[8];
            int ulen = read_utf8_char(c, ubuf, sizeof(ubuf));
            if (ulen > 0) {
                size_t l = strlen(tui->search_query);
                if (l + (size_t)ulen < sizeof(tui->search_query)) {
                    memcpy(tui->search_query + l, ubuf, (size_t)ulen);
                    tui->search_query[l + ulen] = '\0';
                    tui_update_filter(tui, sub);
                }
            }
        }
        return true;
    }

    /* --- Input Subscription URL Mode --- */
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
        } else if (c == 27) {
            tui->in_input_url = false;
            tui->input_url[0] = '\0';
        } else if (c == 127 || c == 8) {
            utf8_backspace(tui->input_url);
        } else if (c == 21) {
            tui->input_url[0] = '\0';
        } else if (c == 23) {
            size_t l = strlen(tui->input_url);
            while (l > 0 && tui->input_url[l - 1] == ' ') l--;
            while (l > 0 && tui->input_url[l - 1] != ' ' && tui->input_url[l - 1] != '/') l--;
            tui->input_url[l] = '\0';
        } else {
            char ubuf[8];
            int ulen = read_utf8_char(c, ubuf, sizeof(ubuf));
            if (ulen > 0) {
                size_t l = strlen(tui->input_url);
                if (l + (size_t)ulen < sizeof(tui->input_url)) {
                    memcpy(tui->input_url + l, ubuf, (size_t)ulen);
                    tui->input_url[l + ulen] = '\0';
                }
            }
        }
        return true;
    }

    /* --- Normal Navigation & Commands --- */
    if (c == key_quit || c == 'Q') {
        return false;
    }

    if (c == 27) {
        char seq[3];
        if (read(STDIN_FILENO, &seq[0], 1) == 1 && read(STDIN_FILENO, &seq[1], 1) == 1) {
            if (seq[0] == '[') {
                if (seq[1] == 'A') {
                    if (tui->selected > 0) tui->selected--;
                } else if (seq[1] == 'B') {
                    if (tui->selected + 1 < (int)tui->filtered_count) tui->selected++;
                } else if (seq[1] == '5' && read(STDIN_FILENO, &seq[2], 1) == 1 && seq[2] == '~') {
                    tui->selected -= 10;
                    if (tui->selected < 0) tui->selected = 0;
                } else if (seq[1] == '6' && read(STDIN_FILENO, &seq[2], 1) == 1 && seq[2] == '~') {
                    tui->selected += 10;
                    if (tui->selected >= (int)tui->filtered_count) tui->selected = (int)tui->filtered_count - 1;
                    if (tui->selected < 0) tui->selected = 0;
                } else if (seq[1] == 'H') {
                    tui->selected = 0;
                } else if (seq[1] == 'F') {
                    tui->selected = tui->filtered_count > 0 ? (int)tui->filtered_count - 1 : 0;
                }
            }
        } else {
            if (tui->search_query[0] != '\0') {
                tui->search_query[0] = '\0';
                tui_update_filter(tui, sub);
            }
        }
        return true;
    }

    if (c == key_up) {
        if (tui->selected > 0) tui->selected--;
    } else if (c == key_down) {
        if (tui->selected + 1 < (int)tui->filtered_count) tui->selected++;
    } else if (c == key_top) {
        tui->selected = 0;
    } else if (c == key_bottom) {
        tui->selected = tui->filtered_count > 0 ? (int)tui->filtered_count - 1 : 0;
    } else if (c == key_search) {
        tui->in_search = true;
        tui->search_query[0] = '\0';
    } else if (c == key_sort) {
        if (tui->filtered_count > 1) {
            int cur_idx = (tui->selected < (int)tui->filtered_count) ?
                          tui->filtered_indices[tui->selected] : -1;

            if (tui->sort_mode == SORT_DEFAULT) {
                tui->sort_mode = SORT_PING_ASC;
                g_sort_sub = sub;
                qsort(tui->filtered_indices, tui->filtered_count, sizeof(int), cmp_ping_asc);
                snprintf(tui->status_msg, sizeof(tui->status_msg), "sorted: lowest ping first");
            } else if (tui->sort_mode == SORT_PING_ASC) {
                tui->sort_mode = SORT_PING_DESC;
                g_sort_sub = sub;
                qsort(tui->filtered_indices, tui->filtered_count, sizeof(int), cmp_ping_desc);
                snprintf(tui->status_msg, sizeof(tui->status_msg), "sorted: highest ping first");
            } else {
                tui->sort_mode = SORT_DEFAULT;
                tui_update_filter(tui, sub);
                snprintf(tui->status_msg, sizeof(tui->status_msg), "sorted: original order");
            }

            if (cur_idx >= 0) {
                for (size_t i = 0; i < tui->filtered_count; i++) {
                    if (tui->filtered_indices[i] == cur_idx) {
                        tui->selected = (int)i;
                        break;
                    }
                }
            }
        }
    } else if (c == key_url) {
        tui->in_input_url = true;
        snprintf(tui->input_url, sizeof(tui->input_url), "%s", sub->url);
    } else if (c == key_sync) {
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
            snprintf(tui->status_msg, sizeof(tui->status_msg), "no url set (%c)", key_url);
        }
    } else if (c == key_disconnect) {
        if (tun->status == TUN_STATUS_CONNECTED) {
            tun_mgr_disconnect(tun);
            snprintf(tui->status_msg, sizeof(tui->status_msg), "disconnected");
        }
    } else if (c == key_fingerprint || c == 'F') {
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
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "relink failed: %.230s", tun->error_msg);
                }
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "fp: %s", tun->fingerprint);
            }
        } else {
            snprintf(tui->status_msg, sizeof(tui->status_msg), "fp: %s", tun->fingerprint);
        }
    } else if (c == key_ping_all) {
        if (tui->filtered_count > 0) {
            snprintf(tui->status_msg, sizeof(tui->status_msg), "pinging %zu nodes...", tui->filtered_count);
            tui_render(tui, sub, tun);
            ping_test_indices_parallel(sub, tui->filtered_indices, tui->filtered_count, ping_timeout_ms);
            snprintf(tui->status_msg, sizeof(tui->status_msg), "ping complete (%zu nodes)", tui->filtered_count);
        }
    } else if (c == key_ping) {
        if (tui->filtered_count > 0 && tui->selected < (int)tui->filtered_count) {
            int sub_idx = tui->filtered_indices[tui->selected];
            server_node_t *node = &sub->nodes[sub_idx];
            snprintf(tui->status_msg, sizeof(tui->status_msg), "ping %.200s...", node->address);
            tui_render(tui, sub, tun);
            int ms = ping_test_node(node, ping_timeout_ms);
            if (ms >= 0) {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "%.200s  %dms", node->address, ms);
            } else if (ms == -2) {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "%.200s  timeout", node->address);
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "%.200s  error", node->address);
            }
        }
    } else if (c == '\r' || c == '\n') {
        if (tui->filtered_count > 0 && tui->selected < (int)tui->filtered_count) {
            int sub_idx = tui->filtered_indices[tui->selected];
            server_node_t *node = &sub->nodes[sub_idx];

            if (tun->status == TUN_STATUS_CONNECTED && strcmp(tun->connected_name, node->name) == 0) {
                tun_mgr_disconnect(tun);
                snprintf(tui->status_msg, sizeof(tui->status_msg), "disconnected");
            } else {
                snprintf(tui->status_msg, sizeof(tui->status_msg), "linking...");
                tui_render(tui, sub, tun);
                if (tun_mgr_connect(tun, node) == 0) {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "linked: %.240s", node->name);
                } else {
                    snprintf(tui->status_msg, sizeof(tui->status_msg), "fault: %.240s", tun->error_msg);
                }
            }
        }
    }

    return true;
}
