#ifndef TUN_MGR_H
#define TUN_MGR_H

#include "sub_parser.h"
#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    TUN_STATUS_DISCONNECTED = 0,
    TUN_STATUS_CONNECTING,
    TUN_STATUS_CONNECTED,
    TUN_STATUS_ERROR
} tun_status_t;

typedef struct {
    tun_status_t status;
    char connected_name[256];
    char server_ip[64];
    char server_ips[16][64];
    int server_ip_count;
    char orig_gw[64];
    char orig_dev[64];
    char tun_dev[32];
    pid_t xray_pid;
    char error_msg[256];
    char xray_bin[256];
    int socks_port;
    int http_port;
    char fingerprint[32];
    bool ipv6_was_enabled;
} tun_manager_t;

void tun_mgr_init(tun_manager_t *mgr);
bool tun_mgr_is_root(void);
const char *tun_mgr_find_xray(tun_manager_t *mgr);
int tun_mgr_connect(tun_manager_t *mgr, const server_node_t *node);
int tun_mgr_disconnect(tun_manager_t *mgr);
void tun_mgr_cleanup(tun_manager_t *mgr);

#endif // TUN_MGR_H
