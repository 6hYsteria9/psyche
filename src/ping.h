#ifndef PING_H
#define PING_H

#include "sub_parser.h"

// Non-blocking TCP ping to server:port, returns latency in ms, or -1 on error, -2 on timeout
int ping_test_tcp(const char *host, int port, int timeout_ms);

// Ping a single node and update node->ping_ms
int ping_test_node(server_node_t *node, int timeout_ms);

#endif // PING_H
