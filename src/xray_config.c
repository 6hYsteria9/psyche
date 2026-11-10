#include "xray_config.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *xray_config_generate_json(const server_node_t *node, const char *tun_dev, int socks_port, int http_port) {
    if (!node) return NULL;
    if (!tun_dev) tun_dev = "psyche0";
    if (socks_port <= 0) socks_port = 10808;
    if (http_port <= 0) http_port = 10809;

    cJSON *root = cJSON_CreateObject();

    // Log
    cJSON *log = cJSON_CreateObject();
    cJSON_AddStringToObject(log, "loglevel", "warning");
    cJSON_AddItemToObject(root, "log", log);

    // Inbounds
    cJSON *inbounds = cJSON_CreateArray();

    // 1. TUN inbound
    cJSON *tun_in = cJSON_CreateObject();
    cJSON_AddStringToObject(tun_in, "tag", "tun-in");
    cJSON_AddStringToObject(tun_in, "protocol", "tun");
    cJSON *tun_settings = cJSON_CreateObject();
    cJSON_AddStringToObject(tun_settings, "name", tun_dev);
    cJSON_AddNumberToObject(tun_settings, "mtu", 1500);
    cJSON_AddStringToObject(tun_settings, "autoOutboundsInterface", "auto");
    cJSON_AddItemToObject(tun_in, "settings", tun_settings);

    cJSON *sniffing = cJSON_CreateObject();
    cJSON_AddBoolToObject(sniffing, "enabled", true);
    cJSON *dest_override = cJSON_CreateArray();
    cJSON_AddItemToArray(dest_override, cJSON_CreateString("http"));
    cJSON_AddItemToArray(dest_override, cJSON_CreateString("tls"));
    cJSON_AddItemToArray(dest_override, cJSON_CreateString("quic"));
    cJSON_AddItemToObject(sniffing, "destOverride", dest_override);
    cJSON_AddBoolToObject(sniffing, "routeOnly", true);
    cJSON_AddItemToObject(tun_in, "sniffing", sniffing);
    cJSON_AddItemToArray(inbounds, tun_in);

    // 2. SOCKS inbound
    cJSON *socks_in = cJSON_CreateObject();
    cJSON_AddStringToObject(socks_in, "tag", "socks-in");
    cJSON_AddStringToObject(socks_in, "protocol", "socks");
    cJSON_AddStringToObject(socks_in, "listen", "127.0.0.1");
    cJSON_AddNumberToObject(socks_in, "port", socks_port);
    cJSON *socks_sett = cJSON_CreateObject();
    cJSON_AddBoolToObject(socks_sett, "udp", true);
    cJSON_AddItemToObject(socks_in, "settings", socks_sett);
    cJSON_AddItemToArray(inbounds, socks_in);

    // 3. HTTP inbound
    cJSON *http_in = cJSON_CreateObject();
    cJSON_AddStringToObject(http_in, "tag", "http-in");
    cJSON_AddStringToObject(http_in, "protocol", "http");
    cJSON_AddStringToObject(http_in, "listen", "127.0.0.1");
    cJSON_AddNumberToObject(http_in, "port", http_port);
    cJSON_AddItemToArray(inbounds, http_in);

    cJSON_AddItemToObject(root, "inbounds", inbounds);

    // Outbounds
    cJSON *outbounds = cJSON_CreateArray();

    // 1. Main Proxy Outbound
    cJSON *proxy = cJSON_CreateObject();
    cJSON_AddStringToObject(proxy, "tag", "proxy");

    cJSON *proxy_settings = cJSON_CreateObject();
    cJSON *stream_settings = cJSON_CreateObject();

    if (node->protocol == PROTO_VLESS) {
        cJSON_AddStringToObject(proxy, "protocol", "vless");
        cJSON *vnext = cJSON_CreateArray();
        cJSON *server = cJSON_CreateObject();
        cJSON_AddStringToObject(server, "address", node->address);
        cJSON_AddNumberToObject(server, "port", node->port);

        cJSON *users = cJSON_CreateArray();
        cJSON *user = cJSON_CreateObject();
        cJSON_AddStringToObject(user, "id", node->uuid_or_pass);
        cJSON_AddStringToObject(user, "encryption", "none");
        if (node->flow[0]) {
            cJSON_AddStringToObject(user, "flow", node->flow);
        }
        cJSON_AddItemToArray(users, user);
        cJSON_AddItemToObject(server, "users", users);
        cJSON_AddItemToArray(vnext, server);
        cJSON_AddItemToObject(proxy_settings, "vnext", vnext);
    } else if (node->protocol == PROTO_VMESS) {
        cJSON_AddStringToObject(proxy, "protocol", "vmess");
        cJSON *vnext = cJSON_CreateArray();
        cJSON *server = cJSON_CreateObject();
        cJSON_AddStringToObject(server, "address", node->address);
        cJSON_AddNumberToObject(server, "port", node->port);

        cJSON *users = cJSON_CreateArray();
        cJSON *user = cJSON_CreateObject();
        cJSON_AddStringToObject(user, "id", node->uuid_or_pass);
        cJSON_AddNumberToObject(user, "alterId", 0);
        cJSON_AddStringToObject(user, "security", "auto");
        cJSON_AddItemToArray(users, user);
        cJSON_AddItemToObject(server, "users", users);
        cJSON_AddItemToArray(vnext, server);
        cJSON_AddItemToObject(proxy_settings, "vnext", vnext);
    } else if (node->protocol == PROTO_TROJAN) {
        cJSON_AddStringToObject(proxy, "protocol", "trojan");
        cJSON *servers = cJSON_CreateArray();
        cJSON *srv = cJSON_CreateObject();
        cJSON_AddStringToObject(srv, "address", node->address);
        cJSON_AddNumberToObject(srv, "port", node->port);
        cJSON_AddStringToObject(srv, "password", node->uuid_or_pass);
        cJSON_AddItemToArray(servers, srv);
        cJSON_AddItemToObject(proxy_settings, "servers", servers);
    } else if (node->protocol == PROTO_SHADOWSOCKS) {
        cJSON_AddStringToObject(proxy, "protocol", "shadowsocks");
        cJSON *servers = cJSON_CreateArray();
        cJSON *srv = cJSON_CreateObject();
        cJSON_AddStringToObject(srv, "address", node->address);
        cJSON_AddNumberToObject(srv, "port", node->port);
        cJSON_AddStringToObject(srv, "method", node->cipher[0] ? node->cipher : "chacha20-ietf-poly1305");
        cJSON_AddStringToObject(srv, "password", node->uuid_or_pass);
        cJSON_AddItemToArray(servers, srv);
        cJSON_AddItemToObject(proxy_settings, "servers", servers);
    }
    cJSON_AddItemToObject(proxy, "settings", proxy_settings);

    // Stream settings
    const char *net_str = "tcp";
    if (node->network == NET_WS) net_str = "ws";
    else if (node->network == NET_GRPC) net_str = "grpc";
    else if (node->network == NET_HTTP) net_str = "http";
    cJSON_AddStringToObject(stream_settings, "network", net_str);

    if (node->security == SEC_REALITY) {
        cJSON_AddStringToObject(stream_settings, "security", "reality");
        cJSON *reality = cJSON_CreateObject();
        cJSON_AddBoolToObject(reality, "show", false);
        cJSON_AddStringToObject(reality, "publicKey", node->pbk);
        cJSON_AddStringToObject(reality, "shortId", node->sid);
        cJSON_AddStringToObject(reality, "serverName", node->sni[0] ? node->sni : node->address);
        cJSON_AddStringToObject(reality, "fingerprint", node->fp[0] ? node->fp : "chrome");
        if (node->spx[0]) {
            cJSON_AddStringToObject(reality, "spiderX", node->spx);
        }
        cJSON_AddItemToObject(stream_settings, "realitySettings", reality);
    } else if (node->security == SEC_TLS) {
        cJSON_AddStringToObject(stream_settings, "security", "tls");
        cJSON *tls = cJSON_CreateObject();
        cJSON_AddStringToObject(tls, "serverName", node->sni[0] ? node->sni : node->address);
        cJSON_AddStringToObject(tls, "fingerprint", node->fp[0] ? node->fp : "chrome");
        cJSON_AddItemToObject(stream_settings, "tlsSettings", tls);
    }

    if (node->network == NET_WS && node->path[0]) {
        cJSON *ws_sett = cJSON_CreateObject();
        cJSON_AddStringToObject(ws_sett, "path", node->path);
        cJSON *headers = cJSON_CreateObject();
        cJSON_AddStringToObject(headers, "Host", node->sni[0] ? node->sni : node->address);
        cJSON_AddItemToObject(ws_sett, "headers", headers);
        cJSON_AddItemToObject(stream_settings, "wsSettings", ws_sett);
    } else if (node->network == NET_GRPC && node->path[0]) {
        cJSON *grpc_sett = cJSON_CreateObject();
        cJSON_AddStringToObject(grpc_sett, "serviceName", node->path);
        cJSON_AddItemToObject(stream_settings, "grpcSettings", grpc_sett);
    }

    if (node->fragment.enabled) {
        cJSON *sockopt = cJSON_CreateObject();
        cJSON_AddStringToObject(sockopt, "dialerProxy", "fragment");
        cJSON_AddItemToObject(stream_settings, "sockopt", sockopt);
    }
    cJSON_AddItemToObject(proxy, "streamSettings", stream_settings);
    cJSON_AddItemToArray(outbounds, proxy);

    // 2. Fragment Outbound (if enabled)
    if (node->fragment.enabled) {
        cJSON *frag = cJSON_CreateObject();
        cJSON_AddStringToObject(frag, "tag", "fragment");
        cJSON_AddStringToObject(frag, "protocol", "freedom");
        cJSON *frag_sett = cJSON_CreateObject();
        cJSON *frag_inner = cJSON_CreateObject();
        cJSON_AddStringToObject(frag_inner, "packets", node->fragment.packets);
        cJSON_AddStringToObject(frag_inner, "length", node->fragment.length);
        cJSON_AddStringToObject(frag_inner, "interval", node->fragment.interval);
        cJSON_AddItemToObject(frag_sett, "fragment", frag_inner);
        cJSON_AddItemToObject(frag, "settings", frag_sett);
        cJSON_AddItemToArray(outbounds, frag);
    }

    // 3. Direct Outbound
    cJSON *direct = cJSON_CreateObject();
    cJSON_AddStringToObject(direct, "tag", "direct");
    cJSON_AddStringToObject(direct, "protocol", "freedom");
    cJSON_AddItemToArray(outbounds, direct);

    // 4. Block Outbound
    cJSON *block = cJSON_CreateObject();
    cJSON_AddStringToObject(block, "tag", "block");
    cJSON_AddStringToObject(block, "protocol", "blackhole");
    cJSON_AddItemToArray(outbounds, block);

    // 5. DNS Outbound
    cJSON *dns_out = cJSON_CreateObject();
    cJSON_AddStringToObject(dns_out, "tag", "dns-out");
    cJSON_AddStringToObject(dns_out, "protocol", "dns");
    cJSON_AddItemToArray(outbounds, dns_out);

    cJSON_AddItemToObject(root, "outbounds", outbounds);

    // Core DNS Block
    cJSON *dns = cJSON_CreateObject();
    cJSON *dns_servers = cJSON_CreateArray();
    cJSON_AddItemToArray(dns_servers, cJSON_CreateString("1.1.1.1"));
    cJSON_AddItemToArray(dns_servers, cJSON_CreateString("8.8.8.8"));
    cJSON_AddItemToArray(dns_servers, cJSON_CreateString("https://1.1.1.1/dns-query"));
    cJSON_AddItemToObject(dns, "servers", dns_servers);
    cJSON_AddItemToObject(root, "dns", dns);

    // Routing
    cJSON *routing = cJSON_CreateObject();
    cJSON_AddStringToObject(routing, "domainStrategy", "AsIs");
    cJSON *rules = cJSON_CreateArray();

    // Rule 1: DNS interception to dns-out
    cJSON *dns_rule = cJSON_CreateObject();
    cJSON_AddStringToObject(dns_rule, "type", "field");
    cJSON *dns_inbounds = cJSON_CreateArray();
    cJSON_AddItemToArray(dns_inbounds, cJSON_CreateString("tun-in"));
    cJSON_AddItemToObject(dns_rule, "inboundTag", dns_inbounds);
    cJSON_AddStringToObject(dns_rule, "port", "53");
    cJSON_AddStringToObject(dns_rule, "outboundTag", "dns-out");
    cJSON_AddItemToArray(rules, dns_rule);

    // Rule 2: General proxy traffic
    cJSON *rule1 = cJSON_CreateObject();
    cJSON_AddStringToObject(rule1, "type", "field");
    cJSON *inbound_tags = cJSON_CreateArray();
    cJSON_AddItemToArray(inbound_tags, cJSON_CreateString("tun-in"));
    cJSON_AddItemToArray(inbound_tags, cJSON_CreateString("socks-in"));
    cJSON_AddItemToArray(inbound_tags, cJSON_CreateString("http-in"));
    cJSON_AddItemToObject(rule1, "inboundTag", inbound_tags);
    cJSON_AddStringToObject(rule1, "outboundTag", "proxy");
    cJSON_AddItemToArray(rules, rule1);

    cJSON_AddItemToObject(routing, "rules", rules);
    cJSON_AddItemToObject(root, "routing", routing);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    return json_str;
}

int xray_config_write_file(const server_node_t *node, const char *filepath, const char *tun_dev) {
    char *json_str = xray_config_generate_json(node, tun_dev, 10808, 10809);
    if (!json_str) return -1;

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        free(json_str);
        return -1;
    }
    fputs(json_str, fp);
    fclose(fp);
    free(json_str);
    return 0;
}
