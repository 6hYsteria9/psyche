#ifndef SUB_PARSER_H
#define SUB_PARSER_H

#include <stddef.h>
#include <stdbool.h>

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_VLESS,
    PROTO_VMESS,
    PROTO_TROJAN,
    PROTO_SHADOWSOCKS
} protocol_t;

typedef enum {
    SEC_NONE = 0,
    SEC_TLS,
    SEC_REALITY
} security_t;

typedef enum {
    NET_TCP = 0,
    NET_WS,
    NET_GRPC,
    NET_HTTP
} network_t;

typedef struct {
    char packets[32];   /* e.g. "tlshello" */
    char length[32];    /* e.g. "10-20" */
    char interval[32];  /* e.g. "0" */
    bool enabled;
} fragment_config_t;

typedef struct {
    protocol_t protocol;
    char name[256];          /* Clean display name (URL decoded) */
    char address[256];       /* Server IP or domain */
    int port;                /* Server port */
    char uuid_or_pass[256];  /* UUID for vless/vmess or password for trojan/ss */
    char flow[64];           /* e.g. "xtls-rprx-vision" */
    security_t security;     /* SEC_REALITY, SEC_TLS, SEC_NONE */
    network_t network;       /* NET_TCP, NET_WS, etc. */
    char sni[256];           /* SNI / serverName */
    char fp[64];             /* TLS fingerprint ("firefox", "chrome", etc.) */
    char pbk[128];           /* Reality public key */
    char sid[64];            /* Reality short ID */
    char spx[128];           /* spiderX */
    char path[256];          /* WebSocket / HTTP path */
    char cipher[64];         /* Shadowsocks cipher/method */
    fragment_config_t fragment;
    int ping_ms;             /* -1 = unmeasured, -2 = timeout, >=0 = latency ms */
    char raw_link[2048];     /* Full original URI */
} server_node_t;

typedef struct {
    char url[1024];
    server_node_t *nodes;
    size_t count;
    size_t capacity;
} subscription_t;

void sub_init(subscription_t *sub);
void sub_free(subscription_t *sub);
void sub_clear(subscription_t *sub);

int sub_fetch_url(subscription_t *sub, const char *url);
int sub_load_file(subscription_t *sub, const char *filepath);
int sub_save_cache(const subscription_t *sub, const char *filepath);
int sub_load_cache(subscription_t *sub, const char *filepath);

int sub_parse_text(subscription_t *sub, const char *text);
int sub_parse_link(subscription_t *sub, const char *link);

const char *protocol_str(protocol_t proto, security_t sec);
void url_decode(char *dst, const char *src, size_t dst_len);
char *base64_decode(const char *input, size_t *out_len);

/* Lightweight string/json tokenizers */
int json_get_str(const char *json, const char *key, char *out, size_t out_len);
int json_get_num(const char *json, const char *key, int *out);

#endif /* SUB_PARSER_H */
