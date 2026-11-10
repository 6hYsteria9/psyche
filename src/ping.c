#define _GNU_SOURCE
#include "ping.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

int ping_test_tcp(const char *host, int port, int timeout_ms) {
    if (!host || port <= 0) return -1;
    if (timeout_ms <= 0) timeout_ms = 1000;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    int ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == 0) {
        // Connected immediately
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        close(sock);
        long ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000 + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;
        return (int)(ms >= 0 ? ms : 0);
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    int poll_ret = poll(&pfd, 1, timeout_ms);
    if (poll_ret == 0) {
        // Timeout
        close(sock);
        return -2;
    } else if (poll_ret < 0) {
        // Error
        close(sock);
        return -1;
    }

    if (pfd.revents & POLLOUT) {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            close(sock);
            long ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000 + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;
            return (int)(ms >= 0 ? ms : 0);
        }
    }

    close(sock);
    return -1;
}

int ping_test_node(server_node_t *node, int timeout_ms) {
    if (!node) return -1;
    int ms = ping_test_tcp(node->address, node->port, timeout_ms);
    node->ping_ms = ms;
    return ms;
}
