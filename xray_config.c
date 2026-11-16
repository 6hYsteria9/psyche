#include "xray_config.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static char cfg_buf[16384];

static void json_escape(char *dst, size_t dst_len, const char *src) {
    if (!dst || dst_len == 0) return;
    size_t d = 0;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    for (size_t s = 0; src[s] != '\0' && d + 6 < dst_len; s++) {
        unsigned char c = (unsigned char)src[s];
        switch (c) {
            case '"':  dst[d++] = '\\'; dst[d++] = '"'; break;
            case '\\': dst[d++] = '\\'; dst[d++] = '\\'; break;
            case '\b': dst[d++] = '\\'; dst[d++] = 'b'; break;
            case '\f': dst[d++] = '\\'; dst[d++] = 'f'; break;
            case '\n': dst[d++] = '\\'; dst[d++] = 'n'; break;
            case '\r': dst[d++] = '\\'; dst[d++] = 'r'; break;
            case '\t': dst[d++] = '\\'; dst[d++] = 't'; break;
            default:
                if (c < 32) {
                    d += snprintf(dst + d, dst_len - d, "\\u%04x", c);
                } else {
                    dst[d++] = (char)c;
                }
                break;
        }
    }
    dst[d] = '\0';
}

static int buf_append(char *buf, size_t cap, size_t *off, const char *fmt, ...) {
    if (*off >= cap) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *off) {
        *off = cap;
        return -1;
    }
    *off += (size_t)n;
    return 0;
}

const char *xray_config_generate_json(const server_node_t *node, const char *tun_dev, int socks_port, int http_port) {
    if (!node) return NULL;
    if (!tun_dev || tun_dev[0] == '\0') tun_dev = default_tun_dev;
    if (socks_port <= 0) socks_port = default_socks_port;
    if (http_port <= 0) http_port = default_http_port;

    char esc_tun[64];
    char esc_addr[512], esc_pass[512], esc_flow[128], esc_cipher[128];
    char esc_sni[512], esc_fp[128], esc_pbk[256], esc_sid[128], esc_spx[256], esc_path[512];
    char esc_frag_pkt[64], esc_frag_len[64], esc_frag_int[64];

    json_escape(esc_tun, sizeof(esc_tun), tun_dev);
    json_escape(esc_addr, sizeof(esc_addr), node->address);
    json_escape(esc_pass, sizeof(esc_pass), node->uuid_or_pass);
    json_escape(esc_flow, sizeof(esc_flow), node->flow);
    json_escape(esc_cipher, sizeof(esc_cipher), node->cipher[0] ? node->cipher : "chacha20-ietf-poly1305");

    const char *sni_val = node->sni[0] ? node->sni : node->address;
    json_escape(esc_sni, sizeof(esc_sni), sni_val);

    const char *fp_val = node->fp[0] ? node->fp : "chrome";
    json_escape(esc_fp, sizeof(esc_fp), fp_val);

    json_escape(esc_pbk, sizeof(esc_pbk), node->pbk);
    json_escape(esc_sid, sizeof(esc_sid), node->sid);
    json_escape(esc_spx, sizeof(esc_spx), node->spx);
    json_escape(esc_path, sizeof(esc_path), node->path);

    json_escape(esc_frag_pkt, sizeof(esc_frag_pkt), node->fragment.packets[0] ? node->fragment.packets : "tlshello");
    json_escape(esc_frag_len, sizeof(esc_frag_len), node->fragment.length[0] ? node->fragment.length : "10-20");
    json_escape(esc_frag_int, sizeof(esc_frag_int), node->fragment.interval[0] ? node->fragment.interval : "0");

    size_t off = 0;
    size_t cap = sizeof(cfg_buf);

    /* Log & Inbounds */
    buf_append(cfg_buf, cap, &off,
        "{\n"
        "  \"log\": {\n"
        "    \"loglevel\": \"warning\"\n"
        "  },\n"
        "  \"inbounds\": [\n"
        "    {\n"
        "      \"tag\": \"tun-in\",\n"
        "      \"protocol\": \"tun\",\n"
        "      \"settings\": {\n"
        "        \"name\": \"%s\",\n"
        "        \"mtu\": 1500,\n"
        "        \"autoOutboundsInterface\": \"auto\"\n"
        "      },\n"
        "      \"sniffing\": {\n"
        "        \"enabled\": true,\n"
        "        \"destOverride\": [\"http\", \"tls\", \"quic\"],\n"
        "        \"routeOnly\": true\n"
        "      }\n"
        "    },\n"
        "    {\n"
        "      \"tag\": \"socks-in\",\n"
        "      \"protocol\": \"socks\",\n"
        "      \"listen\": \"127.0.0.1\",\n"
        "      \"port\": %d,\n"
        "      \"settings\": {\n"
        "        \"udp\": true\n"
        "      }\n"
        "    },\n"
        "    {\n"
        "      \"tag\": \"http-in\",\n"
        "      \"protocol\": \"http\",\n"
        "      \"listen\": \"127.0.0.1\",\n"
        "      \"port\": %d\n"
        "    }\n"
        "  ],\n"
        "  \"outbounds\": [\n"
        "    {\n"
        "      \"tag\": \"proxy\",\n",
        esc_tun, socks_port, http_port);

    /* Proxy protocol settings */
    if (node->protocol == PROTO_VLESS) {
        buf_append(cfg_buf, cap, &off,
            "      \"protocol\": \"vless\",\n"
            "      \"settings\": {\n"
            "        \"vnext\": [{\n"
            "          \"address\": \"%s\",\n"
            "          \"port\": %d,\n"
            "          \"users\": [{\n"
            "            \"id\": \"%s\",\n"
            "            \"encryption\": \"none\"%s%s%s\n"
            "          }]\n"
            "        }]\n"
            "      },\n",
            esc_addr, node->port, esc_pass,
            esc_flow[0] ? ",\n            \"flow\": \"" : "",
            esc_flow[0] ? esc_flow : "",
            esc_flow[0] ? "\"" : "");
    } else if (node->protocol == PROTO_VMESS) {
        buf_append(cfg_buf, cap, &off,
            "      \"protocol\": \"vmess\",\n"
            "      \"settings\": {\n"
            "        \"vnext\": [{\n"
            "          \"address\": \"%s\",\n"
            "          \"port\": %d,\n"
            "          \"users\": [{\n"
            "            \"id\": \"%s\",\n"
            "            \"alterId\": 0,\n"
            "            \"security\": \"auto\"\n"
            "          }]\n"
            "        }]\n"
            "      },\n",
            esc_addr, node->port, esc_pass);
    } else if (node->protocol == PROTO_TROJAN) {
        buf_append(cfg_buf, cap, &off,
            "      \"protocol\": \"trojan\",\n"
            "      \"settings\": {\n"
            "        \"servers\": [{\n"
            "          \"address\": \"%s\",\n"
            "          \"port\": %d,\n"
            "          \"password\": \"%s\"\n"
            "        }]\n"
            "      },\n",
            esc_addr, node->port, esc_pass);
    } else if (node->protocol == PROTO_SHADOWSOCKS) {
        buf_append(cfg_buf, cap, &off,
            "      \"protocol\": \"shadowsocks\",\n"
            "      \"settings\": {\n"
            "        \"servers\": [{\n"
            "          \"address\": \"%s\",\n"
            "          \"port\": %d,\n"
            "          \"method\": \"%s\",\n"
            "          \"password\": \"%s\"\n"
            "        }]\n"
            "      },\n",
            esc_addr, node->port, esc_cipher, esc_pass);
    }

    /* Stream Settings */
    const char *net_str = "tcp";
    if (node->network == NET_WS) net_str = "ws";
    else if (node->network == NET_GRPC) net_str = "grpc";
    else if (node->network == NET_HTTP) net_str = "http";

    buf_append(cfg_buf, cap, &off,
        "      \"streamSettings\": {\n"
        "        \"network\": \"%s\"",
        net_str);

    if (node->security == SEC_REALITY) {
        buf_append(cfg_buf, cap, &off,
            ",\n"
            "        \"security\": \"reality\",\n"
            "        \"realitySettings\": {\n"
            "          \"show\": false,\n"
            "          \"publicKey\": \"%s\",\n"
            "          \"shortId\": \"%s\",\n"
            "          \"serverName\": \"%s\",\n"
            "          \"fingerprint\": \"%s\"%s%s%s\n"
            "        }",
            esc_pbk, esc_sid, esc_sni, esc_fp,
            esc_spx[0] ? ",\n          \"spiderX\": \"" : "",
            esc_spx[0] ? esc_spx : "",
            esc_spx[0] ? "\"" : "");
    } else if (node->security == SEC_TLS) {
        buf_append(cfg_buf, cap, &off,
            ",\n"
            "        \"security\": \"tls\",\n"
            "        \"tlsSettings\": {\n"
            "          \"serverName\": \"%s\",\n"
            "          \"fingerprint\": \"%s\"\n"
            "        }",
            esc_sni, esc_fp);
    }

    if (node->network == NET_WS && node->path[0]) {
        buf_append(cfg_buf, cap, &off,
            ",\n"
            "        \"wsSettings\": {\n"
            "          \"path\": \"%s\",\n"
            "          \"headers\": {\n"
            "            \"Host\": \"%s\"\n"
            "          }\n"
            "        }",
            esc_path, esc_sni);
    } else if (node->network == NET_GRPC && node->path[0]) {
        buf_append(cfg_buf, cap, &off,
            ",\n"
            "        \"grpcSettings\": {\n"
            "          \"serviceName\": \"%s\"\n"
            "        }",
            esc_path);
    }

    if (node->fragment.enabled) {
        buf_append(cfg_buf, cap, &off,
            ",\n"
            "        \"sockopt\": {\n"
            "          \"dialerProxy\": \"fragment\"\n"
            "        }");
    }

    buf_append(cfg_buf, cap, &off, "\n      }\n    }");

    /* Fragment outbound if enabled */
    if (node->fragment.enabled) {
        buf_append(cfg_buf, cap, &off,
            ",\n"
            "    {\n"
            "      \"tag\": \"fragment\",\n"
            "      \"protocol\": \"freedom\",\n"
            "      \"settings\": {\n"
            "        \"fragment\": {\n"
            "          \"packets\": \"%s\",\n"
            "          \"length\": \"%s\",\n"
            "          \"interval\": \"%s\"\n"
            "        }\n"
            "      }\n"
            "    }",
            esc_frag_pkt, esc_frag_len, esc_frag_int);
    }

    /* Direct, Block, DNS outbounds, Core DNS & Routing */
    buf_append(cfg_buf, cap, &off,
        ",\n"
        "    {\n"
        "      \"tag\": \"direct\",\n"
        "      \"protocol\": \"freedom\"\n"
        "    },\n"
        "    {\n"
        "      \"tag\": \"block\",\n"
        "      \"protocol\": \"blackhole\"\n"
        "    },\n"
        "    {\n"
        "      \"tag\": \"dns-out\",\n"
        "      \"protocol\": \"dns\"\n"
        "    }\n"
        "  ],\n"
        "  \"dns\": {\n"
        "    \"servers\": [\n"
        "      \"%s\",\n"
        "      \"%s\",\n"
        "      \"%s\"\n"
        "    ]\n"
        "  },\n"
        "  \"routing\": {\n"
        "    \"domainStrategy\": \"AsIs\",\n"
        "    \"rules\": [\n"
        "      {\n"
        "        \"type\": \"field\",\n"
        "        \"inboundTag\": [\"tun-in\"],\n"
        "        \"port\": \"53\",\n"
        "        \"outboundTag\": \"dns-out\"\n"
        "      },\n"
        "      {\n"
        "        \"type\": \"field\",\n"
        "        \"inboundTag\": [\"tun-in\", \"socks-in\", \"http-in\"],\n"
        "        \"outboundTag\": \"proxy\"\n"
        "      }\n"
        "    ]\n"
        "  }\n"
        "}\n",
        default_dns1, default_dns2, default_doh);

    if (off >= cap) return NULL;
    return cfg_buf;
}

int xray_config_write_file(const server_node_t *node, const char *filepath, const char *tun_dev) {
    const char *json_str = xray_config_generate_json(node, tun_dev, default_socks_port, default_http_port);
    if (!json_str) return -1;

    FILE *fp = fopen(filepath, "w");
    if (!fp) return -1;

    fputs(json_str, fp);
    fclose(fp);
    return 0;
}
