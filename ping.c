#define _GNU_SOURCE
#include "ping.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

#define PING_BATCH_SIZE 64

static int resolve_dest(const char *host, int port, struct sockaddr_in *sa) {
    if (!host || port <= 0 || !sa) return -1;
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)port);

    /* Direct IPv4 check bypassing DNS overhead */
    if (inet_pton(AF_INET, host, &sa->sin_addr) == 1) {
        return 0;
    }

    /* Hostname fallback resolution */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        return -1;
    }

    memcpy(sa, res->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(res);
    return 0;
}

typedef struct {
    int sock;
    server_node_t *node;
    struct timespec start_time;
    bool active;
} ping_slot_t;

static void ping_batch(server_node_t **node_ptrs, size_t count, int timeout_ms) {
    if (!node_ptrs || count == 0) return;

    ping_slot_t slots[PING_BATCH_SIZE];
    struct pollfd pfds[PING_BATCH_SIZE];
    size_t pending = 0;

    for (size_t i = 0; i < count; i++) {
        slots[i].sock = -1;
        slots[i].node = node_ptrs[i];
        slots[i].active = false;
        pfds[i].fd = -1;
        pfds[i].events = POLLOUT;
        pfds[i].revents = 0;

        if (!slots[i].node) continue;

        struct sockaddr_in sa;
        if (resolve_dest(slots[i].node->address, slots[i].node->port, &sa) != 0) {
            slots[i].node->ping_ms = -1;
            continue;
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            slots[i].node->ping_ms = -1;
            continue;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        clock_gettime(CLOCK_MONOTONIC, &slots[i].start_time);
        int ret = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
        if (ret == 0) {
            struct timespec ts_end;
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            close(sock);
            long ms = (ts_end.tv_sec - slots[i].start_time.tv_sec) * 1000 +
                      (ts_end.tv_nsec - slots[i].start_time.tv_nsec) / 1000000;
            slots[i].node->ping_ms = (int)(ms >= 0 ? ms : 0);
            continue;
        }

        if (errno == EINPROGRESS) {
            slots[i].sock = sock;
            slots[i].active = true;
            pfds[i].fd = sock;
            pending++;
        } else {
            close(sock);
            slots[i].node->ping_ms = -1;
        }
    }

    struct timespec batch_start, cur_time;
    clock_gettime(CLOCK_MONOTONIC, &batch_start);

    while (pending > 0) {
        clock_gettime(CLOCK_MONOTONIC, &cur_time);
        long elapsed = (cur_time.tv_sec - batch_start.tv_sec) * 1000 +
                       (cur_time.tv_nsec - batch_start.tv_nsec) / 1000000;
        int rem = timeout_ms - (int)elapsed;
        if (rem <= 0) break;

        int poll_ret = poll(pfds, (nfds_t)count, rem);
        if (poll_ret <= 0) {
            if (poll_ret < 0 && errno == EINTR) continue;
            break;
        }

        for (size_t i = 0; i < count; i++) {
            if (!slots[i].active || pfds[i].fd < 0) continue;
            if (pfds[i].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(slots[i].sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    struct timespec ts_end;
                    clock_gettime(CLOCK_MONOTONIC, &ts_end);
                    long ms = (ts_end.tv_sec - slots[i].start_time.tv_sec) * 1000 +
                              (ts_end.tv_nsec - slots[i].start_time.tv_nsec) / 1000000;
                    slots[i].node->ping_ms = (int)(ms >= 0 ? ms : 0);
                } else {
                    slots[i].node->ping_ms = -1;
                }
                close(slots[i].sock);
                slots[i].sock = -1;
                slots[i].active = false;
                pfds[i].fd = -1;
                pending--;
            }
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (slots[i].active && slots[i].sock >= 0) {
            slots[i].node->ping_ms = -2; /* Timeout */
            close(slots[i].sock);
            slots[i].sock = -1;
            slots[i].active = false;
        }
    }
}

void ping_test_nodes_parallel(server_node_t *nodes, size_t count, int timeout_ms) {
    if (!nodes || count == 0) return;
    if (timeout_ms <= 0) timeout_ms = ping_timeout_ms;

    for (size_t offset = 0; offset < count; offset += PING_BATCH_SIZE) {
        size_t batch = count - offset;
        if (batch > PING_BATCH_SIZE) batch = PING_BATCH_SIZE;

        server_node_t *ptrs[PING_BATCH_SIZE];
        for (size_t i = 0; i < batch; i++) {
            ptrs[i] = &nodes[offset + i];
        }
        ping_batch(ptrs, batch, timeout_ms);
    }
}

void ping_test_indices_parallel(subscription_t *sub, const int *indices, size_t count, int timeout_ms) {
    if (!sub || !indices || count == 0) return;
    if (timeout_ms <= 0) timeout_ms = ping_timeout_ms;

    for (size_t offset = 0; offset < count; offset += PING_BATCH_SIZE) {
        size_t batch = count - offset;
        if (batch > PING_BATCH_SIZE) batch = PING_BATCH_SIZE;

        server_node_t *ptrs[PING_BATCH_SIZE];
        for (size_t i = 0; i < batch; i++) {
            int idx = indices[offset + i];
            ptrs[i] = (idx >= 0 && (size_t)idx < sub->count) ? &sub->nodes[idx] : NULL;
        }
        ping_batch(ptrs, batch, timeout_ms);
    }
}

int ping_test_node(server_node_t *node, int timeout_ms) {
    if (!node) return -1;
    ping_test_nodes_parallel(node, 1, timeout_ms);
    return node->ping_ms;
}

int ping_test_tcp(const char *host, int port, int timeout_ms) {
    if (!host || port <= 0) return -1;
    server_node_t dummy;
    memset(&dummy, 0, sizeof(dummy));
    snprintf(dummy.address, sizeof(dummy.address), "%s", host);
    dummy.port = port;
    return ping_test_node(&dummy, timeout_ms);
}
