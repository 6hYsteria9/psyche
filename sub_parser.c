#define _GNU_SOURCE
#include "sub_parser.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

static int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

char *base64_decode(const char *input, size_t *out_len) {
    if (!input) return NULL;
    size_t in_len = strlen(input);
    size_t alloc_size = (in_len * 3) / 4 + 4;
    char *out = (char *)malloc(alloc_size);
    if (!out) return NULL;

    size_t out_idx = 0;
    int val = 0, valb = -8;
    for (size_t i = 0; i < in_len; i++) {
        char c = input[i];
        if (isspace((unsigned char)c) || c == '=') continue;
        int d = b64_char_value(c);
        if (d < 0) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            out[out_idx++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    out[out_idx] = '\0';
    if (out_len) *out_len = out_idx;
    return out;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void url_decode(char *dst, const char *src, size_t dst_len) {
    if (!dst || !src || dst_len == 0) return;
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < dst_len; s++) {
        if (src[s] == '%' && src[s + 1] && src[s + 2]) {
            int h1 = hex_val(src[s + 1]);
            int h2 = hex_val(src[s + 2]);
            if (h1 >= 0 && h2 >= 0) {
                dst[d++] = (char)((h1 << 4) | h2);
                s += 2;
                continue;
            }
        } else if (src[s] == '+') {
            dst[d++] = ' ';
            continue;
        }
        dst[d++] = src[s];
    }
    dst[d] = '\0';
}

static const char *json_skip_ws(const char *p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

int json_get_str(const char *json, const char *key, char *out, size_t out_len) {
    if (!json || !key || !out || out_len == 0) return 0;
    out[0] = '\0';
    size_t klen = strlen(key);
    const char *p = json;

    while ((p = strstr(p, key)) != NULL) {
        if (p > json && *(p - 1) == '"' && *(p + klen) == '"') {
            const char *c = json_skip_ws(p + klen + 1);
            if (*c == ':') {
                c = json_skip_ws(c + 1);
                if (*c == '"') {
                    c++;
                    size_t d = 0;
                    while (*c && *c != '"' && d + 1 < out_len) {
                        if (*c == '\\' && *(c + 1)) {
                            c++;
                            if (*c == 'n') out[d++] = '\n';
                            else if (*c == 'r') out[d++] = '\r';
                            else if (*c == 't') out[d++] = '\t';
                            else out[d++] = *c;
                        } else {
                            out[d++] = *c;
                        }
                        c++;
                    }
                    out[d] = '\0';
                    return 1;
                }
            }
        }
        p += klen;
    }
    return 0;
}

int json_get_num(const char *json, const char *key, int *out) {
    if (!json || !key || !out) return 0;
    size_t klen = strlen(key);
    const char *p = json;

    while ((p = strstr(p, key)) != NULL) {
        if (p > json && *(p - 1) == '"' && *(p + klen) == '"') {
            const char *c = json_skip_ws(p + klen + 1);
            if (*c == ':') {
                c = json_skip_ws(c + 1);
                if (*c == '"') c++;
                if (*c == '-' || (*c >= '0' && *c <= '9')) {
                    *out = atoi(c);
                    return 1;
                }
            }
        }
        p += klen;
    }
    return 0;
}

void sub_init(subscription_t *sub) {
    if (!sub) return;
    memset(sub, 0, sizeof(subscription_t));
}

void sub_clear(subscription_t *sub) {
    if (!sub) return;
    if (sub->nodes) {
        free(sub->nodes);
        sub->nodes = NULL;
    }
    sub->count = 0;
    sub->capacity = 0;
}

void sub_free(subscription_t *sub) {
    if (!sub) return;
    sub_clear(sub);
}

static bool sub_add_node(subscription_t *sub, const server_node_t *node) {
    if (sub->count >= sub->capacity) {
        size_t new_cap = sub->capacity == 0 ? 16 : sub->capacity * 2;
        server_node_t *new_nodes = (server_node_t *)realloc(sub->nodes, new_cap * sizeof(server_node_t));
        if (!new_nodes) return false;
        sub->nodes = new_nodes;
        sub->capacity = new_cap;
    }
    sub->nodes[sub->count++] = *node;
    return true;
}

static void parse_fragment_json(fragment_config_t *frag, const char *json_str) {
    if (!frag || !json_str) return;
    frag->enabled = false;

    if (!json_get_str(json_str, "packets", frag->packets, sizeof(frag->packets))) {
        snprintf(frag->packets, sizeof(frag->packets), "tlshello");
    }
    if (!json_get_str(json_str, "length", frag->length, sizeof(frag->length))) {
        int len_num = 0;
        if (json_get_num(json_str, "length", &len_num)) {
            snprintf(frag->length, sizeof(frag->length), "%d", len_num);
        } else {
            snprintf(frag->length, sizeof(frag->length), "10-20");
        }
    }
    if (!json_get_str(json_str, "interval", frag->interval, sizeof(frag->interval))) {
        if (!json_get_str(json_str, "delay", frag->interval, sizeof(frag->interval))) {
            int dly_num = 0;
            if (json_get_num(json_str, "interval", &dly_num) || json_get_num(json_str, "delay", &dly_num)) {
                snprintf(frag->interval, sizeof(frag->interval), "%d", dly_num);
            } else {
                snprintf(frag->interval, sizeof(frag->interval), "0");
            }
        }
    }
    frag->enabled = true;
}

/* Parse standard authority "uuid_or_pass@host:port" */
static const char *parse_authority(const char *p, server_node_t *node) {
    const char *at = strchr(p, '@');
    if (!at) return NULL;

    size_t ulen = (size_t)(at - p);
    if (ulen >= sizeof(node->uuid_or_pass)) ulen = sizeof(node->uuid_or_pass) - 1;
    memcpy(node->uuid_or_pass, p, ulen);
    node->uuid_or_pass[ulen] = '\0';

    p = at + 1;
    const char *colon = strchr(p, ':');
    if (!colon) return NULL;

    size_t hlen = (size_t)(colon - p);
    if (hlen >= sizeof(node->address)) hlen = sizeof(node->address) - 1;
    memcpy(node->address, p, hlen);
    node->address[hlen] = '\0';

    p = colon + 1;
    node->port = atoi(p);

    while (*p && *p != '?' && *p != '#') p++;
    return p;
}

static int parse_vless(subscription_t *sub, const char *link) {
    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_VLESS;
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    const char *p = parse_authority(link + 8, &node);
    if (!p) return -1;

    const char *hash = strchr(p, '#');
    if (hash) {
        url_decode(node.name, hash + 1, sizeof(node.name));
    }
    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }

    if (*p == '?') {
        size_t qlen = hash ? (size_t)(hash - (p + 1)) : strlen(p + 1);
        char query[2048];
        if (qlen >= sizeof(query)) qlen = sizeof(query) - 1;
        memcpy(query, p + 1, qlen);
        query[qlen] = '\0';

        char *token = strtok(query, "&");
        while (token) {
            char *eq = strchr(token, '=');
            if (eq) {
                *eq = '\0';
                const char *k = token;
                const char *v = eq + 1;

                if (strcmp(k, "flow") == 0) snprintf(node.flow, sizeof(node.flow), "%s", v);
                else if (strcmp(k, "sni") == 0) snprintf(node.sni, sizeof(node.sni), "%s", v);
                else if (strcmp(k, "fp") == 0) snprintf(node.fp, sizeof(node.fp), "%s", v);
                else if (strcmp(k, "pbk") == 0) snprintf(node.pbk, sizeof(node.pbk), "%s", v);
                else if (strcmp(k, "sid") == 0) snprintf(node.sid, sizeof(node.sid), "%s", v);
                else if (strcmp(k, "spx") == 0) snprintf(node.spx, sizeof(node.spx), "%s", v);
                else if (strcmp(k, "security") == 0) {
                    node.security = (strcmp(v, "reality") == 0) ? SEC_REALITY :
                                    (strcmp(v, "tls") == 0)     ? SEC_TLS : SEC_NONE;
                } else if (strcmp(k, "type") == 0) {
                    node.network = (strcmp(v, "ws") == 0)   ? NET_WS :
                                   (strcmp(v, "grpc") == 0) ? NET_GRPC :
                                   (strcmp(v, "http") == 0) ? NET_HTTP : NET_TCP;
                } else if (strcmp(k, "path") == 0) {
                    url_decode(node.path, v, sizeof(node.path));
                } else if (strcmp(k, "fm") == 0) {
                    char dec_fm[1024];
                    url_decode(dec_fm, v, sizeof(dec_fm));
                    parse_fragment_json(&node.fragment, dec_fm);
                }
            }
            token = strtok(NULL, "&");
        }
    }

    if (node.sni[0] == '\0') {
        snprintf(node.sni, sizeof(node.sni), "%s", node.address);
    }
    if (node.fp[0] == '\0') {
        snprintf(node.fp, sizeof(node.fp), "chrome");
    }

    return sub_add_node(sub, &node) ? 0 : -1;
}

static int parse_vmess(subscription_t *sub, const char *link) {
    const char *p = link + 8;
    size_t dec_len = 0;
    char *decoded = base64_decode(p, &dec_len);
    if (!decoded) return -1;

    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_VMESS;
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    json_get_str(decoded, "ps", node.name, sizeof(node.name));
    json_get_str(decoded, "add", node.address, sizeof(node.address));
    json_get_num(decoded, "port", &node.port);
    json_get_str(decoded, "id", node.uuid_or_pass, sizeof(node.uuid_or_pass));

    char net[32] = {0};
    if (json_get_str(decoded, "net", net, sizeof(net))) {
        if (strcmp(net, "ws") == 0) node.network = NET_WS;
        else if (strcmp(net, "grpc") == 0) node.network = NET_GRPC;
        else if (strcmp(net, "http") == 0) node.network = NET_HTTP;
        else node.network = NET_TCP;
    }

    char tls[32] = {0};
    if (json_get_str(decoded, "tls", tls, sizeof(tls))) {
        if (strcmp(tls, "tls") == 0) node.security = SEC_TLS;
    }

    if (!json_get_str(decoded, "sni", node.sni, sizeof(node.sni)) || node.sni[0] == '\0') {
        snprintf(node.sni, sizeof(node.sni), "%s", node.address);
    }
    json_get_str(decoded, "path", node.path, sizeof(node.path));

    free(decoded);

    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }
    return sub_add_node(sub, &node) ? 0 : -1;
}

static int parse_trojan(subscription_t *sub, const char *link) {
    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_TROJAN;
    node.security = SEC_TLS;
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    const char *p = parse_authority(link + 9, &node);
    if (!p) return -1;

    const char *hash = strchr(p, '#');
    if (hash) {
        url_decode(node.name, hash + 1, sizeof(node.name));
    }
    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }
    snprintf(node.sni, sizeof(node.sni), "%s", node.address);

    return sub_add_node(sub, &node) ? 0 : -1;
}

static int parse_shadowsocks(subscription_t *sub, const char *link) {
    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_SHADOWSOCKS;
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    const char *p = link + 5;
    const char *hash = strchr(p, '#');
    if (hash) {
        url_decode(node.name, hash + 1, sizeof(node.name));
    }

    size_t body_len = hash ? (size_t)(hash - p) : strlen(p);
    char body[2048];
    if (body_len >= sizeof(body)) body_len = sizeof(body) - 1;
    memcpy(body, p, body_len);
    body[body_len] = '\0';

    const char *at = strchr(body, '@');
    if (at) {
        char b64part[512];
        size_t b64_len = (size_t)(at - body);
        if (b64_len >= sizeof(b64part)) b64_len = sizeof(b64part) - 1;
        memcpy(b64part, body, b64_len);
        b64part[b64_len] = '\0';

        size_t dec_len = 0;
        char *decoded = base64_decode(b64part, &dec_len);
        if (decoded) {
            char *colon = strchr(decoded, ':');
            if (colon) {
                *colon = '\0';
                snprintf(node.cipher, sizeof(node.cipher), "%s", decoded);
                snprintf(node.uuid_or_pass, sizeof(node.uuid_or_pass), "%s", colon + 1);
            }
            free(decoded);
        }

        const char *hp = at + 1;
        const char *colon = strchr(hp, ':');
        if (colon) {
            size_t hlen = (size_t)(colon - hp);
            if (hlen >= sizeof(node.address)) hlen = sizeof(node.address) - 1;
            memcpy(node.address, hp, hlen);
            node.address[hlen] = '\0';
            node.port = atoi(colon + 1);
        }
    } else {
        size_t dec_len = 0;
        char *decoded = base64_decode(body, &dec_len);
        if (decoded) {
            char *at_dec = strchr(decoded, '@');
            if (at_dec) {
                *at_dec = '\0';
                char *colon1 = strchr(decoded, ':');
                if (colon1) {
                    *colon1 = '\0';
                    snprintf(node.cipher, sizeof(node.cipher), "%s", decoded);
                    snprintf(node.uuid_or_pass, sizeof(node.uuid_or_pass), "%s", colon1 + 1);
                }
                char *colon2 = strchr(at_dec + 1, ':');
                if (colon2) {
                    *colon2 = '\0';
                    snprintf(node.address, sizeof(node.address), "%s", at_dec + 1);
                    node.port = atoi(colon2 + 1);
                }
            }
            free(decoded);
        }
    }

    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }
    return sub_add_node(sub, &node) ? 0 : -1;
}

int sub_parse_link(subscription_t *sub, const char *link) {
    if (!link) return -1;
    while (*link && isspace((unsigned char)*link)) link++;
    if (*link == '\0') return 0;

    if (strncmp(link, "vless://", 8) == 0) return parse_vless(sub, link);
    if (strncmp(link, "vmess://", 8) == 0) return parse_vmess(sub, link);
    if (strncmp(link, "trojan://", 9) == 0) return parse_trojan(sub, link);
    if (strncmp(link, "ss://", 5) == 0) return parse_shadowsocks(sub, link);

    return -1;
}

int sub_parse_text(subscription_t *sub, const char *text) {
    if (!text) return -1;

    bool seems_raw = (strstr(text, "://") != NULL);
    char *work_buf = NULL;

    if (!seems_raw) {
        size_t dec_len = 0;
        char *decoded = base64_decode(text, &dec_len);
        if (decoded && strstr(decoded, "://")) {
            work_buf = decoded;
        } else {
            if (decoded) free(decoded);
            work_buf = strdup(text);
        }
    } else {
        work_buf = strdup(text);
    }

    if (!work_buf) return -1;

    char *saveptr = NULL;
    char *line = strtok_r(work_buf, "\r\n", &saveptr);
    while (line) {
        while (*line && isspace((unsigned char)*line)) line++;
        if (*line) {
            if (strncmp(line, "vless://", 8) != 0 &&
                strncmp(line, "vmess://", 8) != 0 &&
                strncmp(line, "trojan://", 9) != 0 &&
                strncmp(line, "ss://", 5) != 0) {
                size_t dlen = 0;
                char *line_dec = base64_decode(line, &dlen);
                if (line_dec && strstr(line_dec, "://")) {
                    sub_parse_link(sub, line_dec);
                    free(line_dec);
                } else {
                    if (line_dec) free(line_dec);
                    sub_parse_link(sub, line);
                }
            } else {
                sub_parse_link(sub, line);
            }
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    free(work_buf);
    return (int)sub->count;
}

static char *read_all(int fd, size_t *out_len) {
    size_t cap = 16384;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    ssize_t n;
    while ((n = read(fd, buf + len, cap - len - 1)) > 0) {
        len += (size_t)n;
        if (len + 4096 >= cap) {
            cap *= 2;
            char *new_buf = (char *)realloc(buf, cap);
            if (!new_buf) {
                free(buf);
                return NULL;
            }
            buf = new_buf;
        }
    }
    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

int sub_fetch_url(subscription_t *sub, const char *url) {
    if (!sub || !url || (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)) return -1;
    snprintf(sub->url, sizeof(sub->url), "%s", url);

    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        char timeout_str[16];
        snprintf(timeout_str, sizeof(timeout_str), "%d", http_timeout_s);
        const char *argv[] = {
            "curl", "-s", "-L", "--max-time", timeout_str,
            "-H", "User-Agent: v2rayN/6.23",
            url,
            NULL
        };
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    close(pipefd[1]);
    size_t len = 0;
    char *buffer = read_all(pipefd[0], &len);
    close(pipefd[0]);
    waitpid(pid, NULL, 0);

    if (!buffer || len == 0) {
        if (buffer) free(buffer);
        return -1;
    }

    sub_clear(sub);
    int res = sub_parse_text(sub, buffer);
    free(buffer);
    return res;
}

int sub_load_file(subscription_t *sub, const char *filepath) {
    if (!sub || !filepath) return -1;
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return -1;

    size_t len = 0;
    char *buf = read_all(fd, &len);
    close(fd);

    if (!buf || len == 0) {
        if (buf) free(buf);
        return -1;
    }

    sub_clear(sub);
    int res = sub_parse_text(sub, buf);
    free(buf);
    return res;
}

int sub_save_cache(const subscription_t *sub, const char *filepath) {
    if (!sub || !filepath) return -1;
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    for (size_t i = 0; i < sub->count; i++) {
        if (sub->nodes[i].raw_link[0]) {
            dprintf(fd, "%s\n", sub->nodes[i].raw_link);
        }
    }
    close(fd);
    return 0;
}

int sub_load_cache(subscription_t *sub, const char *filepath) {
    return sub_load_file(sub, filepath);
}

const char *protocol_str(protocol_t proto, security_t sec) {
    switch (proto) {
        case PROTO_VLESS:
            return (sec == SEC_REALITY) ? "VLESS/Reality" :
                   (sec == SEC_TLS)     ? "VLESS/TLS" : "VLESS";
        case PROTO_VMESS:
            return (sec == SEC_TLS)     ? "VMess/TLS" : "VMess";
        case PROTO_TROJAN:
            return "Trojan";
        case PROTO_SHADOWSOCKS:
            return "Shadowsocks";
        default:
            return "Unknown";
    }
}
