#define _GNU_SOURCE
#include "tun_mgr.h"
#include "xray_config.h"

#if defined(__has_include) && __has_include("config.h")
#include "config.h"
#else
#include "../config.def.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define CONFIG_PATH "/tmp/psyche_xray.json"
#define LOG_PATH    "/tmp/psyche_xray.log"
#define RESOLV_BAK  "/tmp/psyche_resolv.bak"

void tun_mgr_init(tun_manager_t *mgr) {
    if (!mgr) return;
    memset(mgr, 0, sizeof(tun_manager_t));
    mgr->status = TUN_STATUS_DISCONNECTED;
    snprintf(mgr->tun_dev, sizeof(mgr->tun_dev), "%s", default_tun_dev);
    mgr->socks_port = default_socks_port;
    mgr->http_port = default_http_port;
    snprintf(mgr->fingerprint, sizeof(mgr->fingerprint), "%s", fingerprints[0]);
    tun_mgr_find_xray(mgr);
}

bool tun_mgr_is_root(void) {
    return geteuid() == 0;
}

const char *tun_mgr_find_xray(tun_manager_t *mgr) {
    if (mgr->xray_bin[0] != '\0' && access(mgr->xray_bin, X_OK) == 0) {
        return mgr->xray_bin;
    }

    const char *candidates[] = {
        "/usr/bin/xray",
        "/usr/local/bin/xray",
        "/opt/xray/xray",
        "/usr/bin/xray-core",
        NULL
    };

    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            snprintf(mgr->xray_bin, sizeof(mgr->xray_bin), "%s", candidates[i]);
            return mgr->xray_bin;
        }
    }

    // Try `which xray` via popen
    FILE *fp = popen("which xray 2>/dev/null", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp)) {
            size_t l = strlen(buf);
            while (l > 0 && (buf[l - 1] == '\r' || buf[l - 1] == '\n')) {
                buf[--l] = '\0';
            }
            if (l > 0 && access(buf, X_OK) == 0) {
                snprintf(mgr->xray_bin, sizeof(mgr->xray_bin), "%s", buf);
                pclose(fp);
                return mgr->xray_bin;
            }
        }
        pclose(fp);
    }

    snprintf(mgr->xray_bin, sizeof(mgr->xray_bin), "xray");
    return mgr->xray_bin;
}

static int run_cmd(const char *cmd) {
    int ret = system(cmd);
    if (WIFEXITED(ret)) return WEXITSTATUS(ret);
    return -1;
}

static int run_privileged(const char *cmd) {
    if (geteuid() == 0) {
        return run_cmd(cmd);
    }
    char buf[1024];
    // Check if doas exists
    if (access("/usr/bin/doas", X_OK) == 0) {
        snprintf(buf, sizeof(buf), "doas %s", cmd);
    } else {
        snprintf(buf, sizeof(buf), "sudo %s", cmd);
    }
    return run_cmd(buf);
}

static int resolve_all_hosts(tun_manager_t *mgr, const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(host, NULL, &hints, &res);
    if (status != 0 || !res) return -1;

    mgr->server_ip_count = 0;
    for (struct addrinfo *p = res; p != NULL && mgr->server_ip_count < 16; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        char ip[64];
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip));
        // Check for duplicates
        bool duplicate = false;
        for (int k = 0; k < mgr->server_ip_count; k++) {
            if (strcmp(mgr->server_ips[k], ip) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            snprintf(mgr->server_ips[mgr->server_ip_count], sizeof(mgr->server_ips[0]), "%s", ip);
            mgr->server_ip_count++;
        }
    }
    freeaddrinfo(res);

    if (mgr->server_ip_count > 0) {
        snprintf(mgr->server_ip, sizeof(mgr->server_ip), "%s", mgr->server_ips[0]);
        return 0;
    }
    return -1;
}

static int find_default_route(char *gw, size_t gw_len, char *dev, size_t dev_len) {
    FILE *fp = popen("ip -4 route show default 2>/dev/null", "r");
    if (!fp) return -1;

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        // e.g. "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
        char *via_pos = strstr(line, "via ");
        char *dev_pos = strstr(line, "dev ");
        if (via_pos) {
            via_pos += 4;
            char *sp = strchr(via_pos, ' ');
            if (sp) {
                size_t l = sp - via_pos;
                if (l >= gw_len) l = gw_len - 1;
                strncpy(gw, via_pos, l);
                gw[l] = '\0';
            }
        }
        if (dev_pos) {
            dev_pos += 4;
            char *sp = strchr(dev_pos, ' ');
            size_t l = sp ? (size_t)(sp - dev_pos) : strlen(dev_pos);
            while (l > 0 && (dev_pos[l-1] == '\r' || dev_pos[l-1] == '\n' || dev_pos[l-1] == ' ')) l--;
            if (l >= dev_len) l = dev_len - 1;
            strncpy(dev, dev_pos, l);
            dev[l] = '\0';
        }
        if (gw[0] && dev[0]) {
            found = true;
            break;
        }
    }
    pclose(fp);
    return found ? 0 : -1;
}

int tun_mgr_connect(tun_manager_t *mgr, const server_node_t *node) {
    if (!mgr || !node) return -1;
    if (mgr->status == TUN_STATUS_CONNECTED) {
        tun_mgr_disconnect(mgr);
    }

    mgr->status = TUN_STATUS_CONNECTING;
    snprintf(mgr->connected_name, sizeof(mgr->connected_name), "%s", node->name);
    mgr->error_msg[0] = '\0';

    // 1. Resolve remote server address
    if (resolve_all_hosts(mgr, node->address) != 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Failed to resolve host: %.100s", node->address);
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    // 2. Discover default route
    if (find_default_route(mgr->orig_gw, sizeof(mgr->orig_gw), mgr->orig_dev, sizeof(mgr->orig_dev)) != 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Could not determine default gateway/interface");
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    // 3. Prepare node config with resolved IP (breaks circular DNS deadlock in Xray)
    server_node_t effective_node = *node;
    snprintf(effective_node.address, sizeof(effective_node.address), "%s", mgr->server_ip);
    if (effective_node.sni[0] == '\0') {
        snprintf(effective_node.sni, sizeof(effective_node.sni), "%s", node->address);
    }
    if (mgr->fingerprint[0] != '\0') {
        snprintf(effective_node.fp, sizeof(effective_node.fp), "%s", mgr->fingerprint);
    }

    // Write Xray configuration
    if (xray_config_write_file(&effective_node, CONFIG_PATH, mgr->tun_dev) != 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Failed to write Xray config to %s", CONFIG_PATH);
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    // 4. Start Xray process
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "fork() failed: %s", strerror(errno));
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    if (pid == 0) {
        // Child process
#ifdef __linux__
        // Ensure child Xray exits if parent Psyche dies
        prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
        int log_fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        execlp(mgr->xray_bin, mgr->xray_bin, "run", "-c", CONFIG_PATH, (char *)NULL);
        // If execlp fails
        fprintf(stderr, "execlp(%s) failed: %s\n", mgr->xray_bin, strerror(errno));
        _exit(127);
    }

    mgr->xray_pid = pid;

    // 5. Wait for TUN device to be created by Xray
    char sys_tun_path[128];
    snprintf(sys_tun_path, sizeof(sys_tun_path), "/sys/class/net/%s", mgr->tun_dev);

    bool dev_ready = false;
    for (int i = 0; i < 30; i++) {
        usleep(100000); // 100ms
        // Check if child died
        int child_status = 0;
        pid_t wp = waitpid(pid, &child_status, WNOHANG);
        if (wp == pid) {
            // Process terminated
            mgr->xray_pid = 0;
            char log_snippet[200] = {0};
            FILE *lf = fopen(LOG_PATH, "r");
            if (lf) {
                size_t bytes = fread(log_snippet, 1, sizeof(log_snippet) - 1, lf);
                log_snippet[bytes] = '\0';
                fclose(lf);
            }
            snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Xray exited early: %.150s", log_snippet);
            mgr->status = TUN_STATUS_ERROR;
            return -1;
        }

        if (access(sys_tun_path, F_OK) == 0) {
            dev_ready = true;
            break;
        }
    }

    if (!dev_ready) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "TUN device %s was not created by Xray", mgr->tun_dev);
        tun_mgr_disconnect(mgr);
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    // 6. Configure network interface & routing
    char cmd[512];

    // Bring up TUN
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", mgr->tun_dev);
    run_privileged(cmd);

    // Assign IP
    snprintf(cmd, sizeof(cmd), "ip addr add 172.19.0.1/30 dev %s", mgr->tun_dev);
    run_privileged(cmd);

    // Direct routes to all server IPs via original gateway (prevents routing loops)
    for (int i = 0; i < mgr->server_ip_count; i++) {
        snprintf(cmd, sizeof(cmd), "ip route add %s via %s dev %s 2>/dev/null",
                 mgr->server_ips[i], mgr->orig_gw, mgr->orig_dev);
        run_privileged(cmd);
    }

    // Route 0.0.0.0/1 and 128.0.0.0/1 through TUN
    snprintf(cmd, sizeof(cmd), "ip route add 0.0.0.0/1 dev %s", mgr->tun_dev);
    run_privileged(cmd);

    snprintf(cmd, sizeof(cmd), "ip route add 128.0.0.0/1 dev %s", mgr->tun_dev);
    run_privileged(cmd);

    // Route DNS 1.1.1.1 and 8.8.8.8 through TUN
    snprintf(cmd, sizeof(cmd), "ip route add 1.1.1.1 dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add 8.8.8.8 dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    // Backup and set /etc/resolv.conf
    run_privileged("cp /etc/resolv.conf " RESOLV_BAK " 2>/dev/null");
    run_privileged("sh -c 'printf \"nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n\" > /etc/resolv.conf'");

    // Shield against IPv6 leaks by disabling IPv6 during VPN link
    FILE *fp_v6 = fopen("/proc/sys/net/ipv6/conf/all/disable_ipv6", "r");
    if (fp_v6) {
        char v6_val = '0';
        if (fread(&v6_val, 1, 1, fp_v6) == 1 && v6_val == '0') {
            mgr->ipv6_was_enabled = true;
            run_privileged("sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1");
        }
        fclose(fp_v6);
    }

    mgr->status = TUN_STATUS_CONNECTED;
    return 0;
}

int tun_mgr_disconnect(tun_manager_t *mgr) {
    if (!mgr) return -1;

    char cmd[512];

    // Delete routes
    snprintf(cmd, sizeof(cmd), "ip route del 0.0.0.0/1 dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    snprintf(cmd, sizeof(cmd), "ip route del 128.0.0.0/1 dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    snprintf(cmd, sizeof(cmd), "ip route del 1.1.1.1 dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    snprintf(cmd, sizeof(cmd), "ip route del 8.8.8.8 dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    for (int i = 0; i < mgr->server_ip_count; i++) {
        snprintf(cmd, sizeof(cmd), "ip route del %s via %s dev %s 2>/dev/null",
                 mgr->server_ips[i], mgr->orig_gw, mgr->orig_dev);
        run_privileged(cmd);
    }
    mgr->server_ip_count = 0;

    // Restore DNS
    if (access(RESOLV_BAK, F_OK) == 0) {
        run_privileged("cp " RESOLV_BAK " /etc/resolv.conf 2>/dev/null");
        run_privileged("rm -f " RESOLV_BAK " 2>/dev/null");
    }

    // Restore IPv6 state if it was shielded
    if (mgr->ipv6_was_enabled) {
        run_privileged("sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1");
        mgr->ipv6_was_enabled = false;
    }

    // Bring down interface
    snprintf(cmd, sizeof(cmd), "ip link set dev %s down 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    snprintf(cmd, sizeof(cmd), "ip link del dev %s 2>/dev/null", mgr->tun_dev);
    run_privileged(cmd);

    // Terminate Xray process
    if (mgr->xray_pid > 0) {
        kill(mgr->xray_pid, SIGTERM);
        for (int i = 0; i < 10; i++) {
            usleep(100000); // 100ms
            int status = 0;
            if (waitpid(mgr->xray_pid, &status, WNOHANG) == mgr->xray_pid) {
                mgr->xray_pid = 0;
                break;
            }
        }
        if (mgr->xray_pid > 0) {
            kill(mgr->xray_pid, SIGKILL);
            waitpid(mgr->xray_pid, NULL, 0);
            mgr->xray_pid = 0;
        }
    }

    unlink(CONFIG_PATH);

    mgr->status = TUN_STATUS_DISCONNECTED;
    mgr->connected_name[0] = '\0';
    mgr->server_ip[0] = '\0';
    return 0;
}

void tun_mgr_cleanup(tun_manager_t *mgr) {
    if (!mgr) return;
    if (mgr->status == TUN_STATUS_CONNECTED || mgr->xray_pid > 0) {
        tun_mgr_disconnect(mgr);
    }
}
