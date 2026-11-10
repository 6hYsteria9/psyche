#ifndef XRAY_CONFIG_H
#define XRAY_CONFIG_H

#include "sub_parser.h"

// Generate JSON string for Xray config from server node
char *xray_config_generate_json(const server_node_t *node, const char *tun_dev, int socks_port, int http_port);

// Write Xray config directly to a file (e.g. /tmp/psyche_xray.json)
int xray_config_write_file(const server_node_t *node, const char *filepath, const char *tun_dev);

#endif // XRAY_CONFIG_H
