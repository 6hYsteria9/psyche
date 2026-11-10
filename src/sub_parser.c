#define _GNU_SOURCE
#include "sub_parser.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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
    // Allocate enough memory
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
    frag->enabled = false;
    cJSON *root = cJSON_Parse(json_str);
    if (!root) return;

    cJSON *settings = NULL;
    // Check if it's {"tcp":[{"type":"fragment","settings":{...}}]}
    cJSON *tcp = cJSON_GetObjectItem(root, "tcp");
    if (tcp && cJSON_IsArray(tcp)) {
        cJSON *elem = cJSON_GetArrayItem(tcp, 0);
        if (elem) {
            settings = cJSON_GetObjectItem(elem, "settings");
        }
    }
    // Or direct {"settings":{...}} or {"fragment":{...}}
    if (!settings) {
        settings = cJSON_GetObjectItem(root, "settings");
    }
    if (!settings) {
        settings = cJSON_GetObjectItem(root, "fragment");
    }
    if (!settings && cJSON_IsObject(root)) {
        settings = root;
    }

    if (settings) {
        cJSON *pkt = cJSON_GetObjectItem(settings, "packets");
        cJSON *len = cJSON_GetObjectItem(settings, "length");
        cJSON *dly = cJSON_GetObjectItem(settings, "delay");
        if (!dly) dly = cJSON_GetObjectItem(settings, "interval");

        if (pkt && cJSON_IsString(pkt)) {
            snprintf(frag->packets, sizeof(frag->packets), "%s", pkt->valuestring);
        } else {
            snprintf(frag->packets, sizeof(frag->packets), "tlshello");
        }

        if (len && cJSON_IsString(len)) {
            snprintf(frag->length, sizeof(frag->length), "%s", len->valuestring);
        } else if (len && cJSON_IsNumber(len)) {
            snprintf(frag->length, sizeof(frag->length), "%d", (int)len->valuedouble);
        } else {
            snprintf(frag->length, sizeof(frag->length), "10-20");
        }

        if (dly && cJSON_IsString(dly)) {
            snprintf(frag->interval, sizeof(frag->interval), "%s", dly->valuestring);
        } else if (dly && cJSON_IsNumber(dly)) {
            snprintf(frag->interval, sizeof(frag->interval), "%d", (int)dly->valuedouble);
        } else {
            snprintf(frag->interval, sizeof(frag->interval), "0");
        }

        frag->enabled = true;
    }
    cJSON_Delete(root);
}

static int parse_vless(subscription_t *sub, const char *link) {
    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_VLESS;
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    const char *p = link + 8; // skip "vless://"
    const char *at = strchr(p, '@');
    if (!at) return -1;

    size_t uuid_len = at - p;
    if (uuid_len >= sizeof(node.uuid_or_pass)) uuid_len = sizeof(node.uuid_or_pass) - 1;
    strncpy(node.uuid_or_pass, p, uuid_len);
    node.uuid_or_pass[uuid_len] = '\0';

    p = at + 1;
    const char *colon = strchr(p, ':');
    if (!colon) return -1;

    size_t host_len = colon - p;
    if (host_len >= sizeof(node.address)) host_len = sizeof(node.address) - 1;
    strncpy(node.address, p, host_len);
    node.address[host_len] = '\0';

    p = colon + 1;
    node.port = atoi(p);

    const char *qmark = strchr(p, '?');
    const char *hash = strchr(p, '#');

    if (hash) {
        url_decode(node.name, hash + 1, sizeof(node.name));
    }
    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }

    if (qmark) {
        size_t query_len = hash ? (size_t)(hash - (qmark + 1)) : strlen(qmark + 1);
        char *query = (char *)malloc(query_len + 1);
        if (query) {
            strncpy(query, qmark + 1, query_len);
            query[query_len] = '\0';

            char *token = strtok(query, "&");
            while (token) {
                char *eq = strchr(token, '=');
                if (eq) {
                    *eq = '\0';
                    const char *key = token;
                    const char *val = eq + 1;

                    if (strcmp(key, "flow") == 0) {
                        snprintf(node.flow, sizeof(node.flow), "%s", val);
                    } else if (strcmp(key, "security") == 0) {
                        if (strcmp(val, "reality") == 0) node.security = SEC_REALITY;
                        else if (strcmp(val, "tls") == 0) node.security = SEC_TLS;
                        else node.security = SEC_NONE;
                    } else if (strcmp(key, "sni") == 0) {
                        snprintf(node.sni, sizeof(node.sni), "%s", val);
                    } else if (strcmp(key, "fp") == 0) {
                        snprintf(node.fp, sizeof(node.fp), "%s", val);
                    } else if (strcmp(key, "pbk") == 0) {
                        snprintf(node.pbk, sizeof(node.pbk), "%s", val);
                    } else if (strcmp(key, "sid") == 0) {
                        snprintf(node.sid, sizeof(node.sid), "%s", val);
                    } else if (strcmp(key, "spx") == 0) {
                        snprintf(node.spx, sizeof(node.spx), "%s", val);
                    } else if (strcmp(key, "type") == 0) {
                        if (strcmp(val, "ws") == 0) node.network = NET_WS;
                        else if (strcmp(val, "grpc") == 0) node.network = NET_GRPC;
                        else if (strcmp(val, "http") == 0) node.network = NET_HTTP;
                        else node.network = NET_TCP;
                    } else if (strcmp(key, "path") == 0) {
                        url_decode(node.path, val, sizeof(node.path));
                    } else if (strcmp(key, "fm") == 0) {
                        char dec_fm[1024];
                        url_decode(dec_fm, val, sizeof(dec_fm));
                        parse_fragment_json(&node.fragment, dec_fm);
                    }
                }
                token = strtok(NULL, "&");
            }
            free(query);
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
    const char *p = link + 8; // skip "vmess://"
    size_t dec_len = 0;
    char *decoded = base64_decode(p, &dec_len);
    if (!decoded) return -1;

    cJSON *root = cJSON_Parse(decoded);
    free(decoded);
    if (!root) return -1;

    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_VMESS;
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    cJSON *item = cJSON_GetObjectItem(root, "ps");
    if (item && cJSON_IsString(item)) snprintf(node.name, sizeof(node.name), "%s", item->valuestring);

    item = cJSON_GetObjectItem(root, "add");
    if (item && cJSON_IsString(item)) snprintf(node.address, sizeof(node.address), "%s", item->valuestring);

    item = cJSON_GetObjectItem(root, "port");
    if (item) {
        if (cJSON_IsNumber(item)) node.port = (int)item->valuedouble;
        else if (cJSON_IsString(item)) node.port = atoi(item->valuestring);
    }

    item = cJSON_GetObjectItem(root, "id");
    if (item && cJSON_IsString(item)) snprintf(node.uuid_or_pass, sizeof(node.uuid_or_pass), "%s", item->valuestring);

    item = cJSON_GetObjectItem(root, "net");
    if (item && cJSON_IsString(item)) {
        if (strcmp(item->valuestring, "ws") == 0) node.network = NET_WS;
        else if (strcmp(item->valuestring, "grpc") == 0) node.network = NET_GRPC;
        else node.network = NET_TCP;
    }

    item = cJSON_GetObjectItem(root, "tls");
    if (item && cJSON_IsString(item) && strcmp(item->valuestring, "tls") == 0) {
        node.security = SEC_TLS;
    }

    item = cJSON_GetObjectItem(root, "sni");
    if (item && cJSON_IsString(item)) snprintf(node.sni, sizeof(node.sni), "%s", item->valuestring);
    else snprintf(node.sni, sizeof(node.sni), "%s", node.address);

    item = cJSON_GetObjectItem(root, "path");
    if (item && cJSON_IsString(item)) snprintf(node.path, sizeof(node.path), "%s", item->valuestring);

    cJSON_Delete(root);

    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }
    return sub_add_node(sub, &node) ? 0 : -1;
}

static int parse_trojan(subscription_t *sub, const char *link) {
    server_node_t node;
    memset(&node, 0, sizeof(node));
    node.protocol = PROTO_TROJAN;
    node.security = SEC_TLS; // trojan is TLS by default
    node.ping_ms = -1;
    snprintf(node.raw_link, sizeof(node.raw_link), "%s", link);

    const char *p = link + 9; // skip "trojan://"
    const char *at = strchr(p, '@');
    if (!at) return -1;

    size_t pass_len = at - p;
    if (pass_len >= sizeof(node.uuid_or_pass)) pass_len = sizeof(node.uuid_or_pass) - 1;
    strncpy(node.uuid_or_pass, p, pass_len);
    node.uuid_or_pass[pass_len] = '\0';

    p = at + 1;
    const char *colon = strchr(p, ':');
    if (!colon) return -1;

    size_t host_len = colon - p;
    if (host_len >= sizeof(node.address)) host_len = sizeof(node.address) - 1;
    strncpy(node.address, p, host_len);
    node.address[host_len] = '\0';

    p = colon + 1;
    node.port = atoi(p);

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

    const char *p = link + 5; // skip "ss://"
    const char *hash = strchr(p, '#');
    if (hash) {
        url_decode(node.name, hash + 1, sizeof(node.name));
    }

    size_t body_len = hash ? (size_t)(hash - p) : strlen(p);
    char *body = (char *)malloc(body_len + 1);
    if (!body) return -1;
    strncpy(body, p, body_len);
    body[body_len] = '\0';

    const char *at = strchr(body, '@');
    if (at) {
        // ss://[base64(method:password)]@host:port
        char b64part[256];
        size_t b64_len = at - body;
        if (b64_len >= sizeof(b64part)) b64_len = sizeof(b64part) - 1;
        strncpy(b64part, body, b64_len);
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
            size_t hlen = colon - hp;
            if (hlen >= sizeof(node.address)) hlen = sizeof(node.address) - 1;
            strncpy(node.address, hp, hlen);
            node.address[hlen] = '\0';
            node.port = atoi(colon + 1);
        }
    } else {
        // ss://[base64(method:password@host:port)]
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
    free(body);

    if (node.name[0] == '\0') {
        snprintf(node.name, sizeof(node.name), "%.240s:%d", node.address, node.port);
    }
    return sub_add_node(sub, &node) ? 0 : -1;
}

int sub_parse_link(subscription_t *sub, const char *link) {
    if (!link) return -1;
    // Trim leading whitespace
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

    // Check if the whole text is base64
    bool seems_raw = (strstr(text, "vless://") != NULL ||
                      strstr(text, "vmess://") != NULL ||
                      strstr(text, "trojan://") != NULL ||
                      strstr(text, "ss://") != NULL);

    char *work_buf = NULL;
    if (!seems_raw) {
        size_t dec_len = 0;
        char *decoded = base64_decode(text, &dec_len);
        if (decoded && (strstr(decoded, "://") != NULL)) {
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
            // Check if this line itself is base64 encoded
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

static bool is_valid_url(const char *url) {
    if (!url) return false;
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        return false;
    }
    for (const char *p = url; *p; p++) {
        if (*p == '\'' || *p == '"' || *p == '`' || *p == '$' ||
            *p == ';' || *p == '|' || *p == '&' || *p == '\n' ||
            *p == '\r' || (unsigned char)*p < 32 || (unsigned char)*p > 126) {
            return false;
        }
    }
    return true;
}

int sub_fetch_url(subscription_t *sub, const char *url) {
    if (!sub || !url || !is_valid_url(url)) return -1;
    snprintf(sub->url, sizeof(sub->url), "%s", url);

    // Call curl via popen
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "curl -s -L --max-time 15 -H 'User-Agent: v2rayN/6.23' '%s'", url);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    size_t cap = 65536;
    size_t len = 0;
    char *buffer = (char *)malloc(cap);
    if (!buffer) {
        pclose(fp);
        return -1;
    }

    char chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        if (len + n + 1 >= cap) {
            cap *= 2;
            char *new_buf = (char *)realloc(buffer, cap);
            if (!new_buf) {
                free(buffer);
                pclose(fp);
                return -1;
            }
            buffer = new_buf;
        }
        memcpy(buffer + len, chunk, n);
        len += n;
    }
    buffer[len] = '\0';
    pclose(fp);

    if (len == 0) {
        free(buffer);
        return -1;
    }

    sub_clear(sub);
    int res = sub_parse_text(sub, buffer);
    free(buffer);
    return res;
}

int sub_load_file(subscription_t *sub, const char *filepath) {
    if (!sub || !filepath) return -1;
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        return -1;
    }

    char *buf = (char *)malloc(size + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t r = fread(buf, 1, size, f);
    buf[r] = '\0';
    fclose(f);

    sub_clear(sub);
    int res = sub_parse_text(sub, buf);
    free(buf);
    return res;
}

int sub_save_cache(const subscription_t *sub, const char *filepath) {
    if (!sub || !filepath) return -1;
    FILE *f = fopen(filepath, "w");
    if (!f) return -1;

    for (size_t i = 0; i < sub->count; i++) {
        if (sub->nodes[i].raw_link[0]) {
            fprintf(f, "%s\n", sub->nodes[i].raw_link);
        }
    }
    fclose(f);
    return 0;
}

int sub_load_cache(subscription_t *sub, const char *filepath) {
    return sub_load_file(sub, filepath);
}

const char *protocol_str(protocol_t proto, security_t sec) {
    switch (proto) {
        case PROTO_VLESS:
            if (sec == SEC_REALITY) return "VLESS/Reality";
            if (sec == SEC_TLS) return "VLESS/TLS";
            return "VLESS";
        case PROTO_VMESS:
            if (sec == SEC_TLS) return "VMess/TLS";
            return "VMess";
        case PROTO_TROJAN:
            return "Trojan";
        case PROTO_SHADOWSOCKS:
            return "Shadowsocks";
        default:
            return "Unknown";
    }
}
