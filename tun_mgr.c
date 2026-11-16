#define _GNU_SOURCE
#include "tun_mgr.h"
#include "xray_config.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static uid_t g_orig_uid = 0;
static gid_t g_orig_gid = 0;
static bool  g_has_dropped_priv = false;

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

bool tun_mgr_has_net_admin(void) {
    if (geteuid() == 0) return true;
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct data[2] = {0};
    if (syscall(SYS_capget, &hdr, data) == 0) {
        if (data[0].effective & (1 << CAP_NET_ADMIN)) {
            return true;
        }
    }
    return false;
}

void tun_mgr_priv_init(void) {
    const char *s_uid = getenv("SUDO_UID");
    const char *s_gid = getenv("SUDO_GID");
    if (s_uid && s_gid && geteuid() == 0) {
        uid_t target_uid = (uid_t)atoi(s_uid);
        gid_t target_gid = (gid_t)atoi(s_gid);
        if (target_uid > 0) {
            g_orig_uid = target_uid;
            g_orig_gid = target_gid;
            g_has_dropped_priv = true;
            if (setegid(target_gid) != 0 || seteuid(target_uid) != 0) {
                g_has_dropped_priv = false;
            }
        }
    }
}

void tun_mgr_priv_elevate(void) {
    if (g_has_dropped_priv) {
        if (seteuid(0) != 0) {
            /* ignore error if not allowed */
        }
        if (setegid(0) != 0) {
            /* ignore error if not allowed */
        }
    }
}

void tun_mgr_priv_drop(void) {
    if (g_has_dropped_priv) {
        if (setegid(g_orig_gid) != 0) {
            /* ignore error */
        }
        if (seteuid(g_orig_uid) != 0) {
            /* ignore error */
        }
    }
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

    const char *path = getenv("PATH");
    if (path) {
        char pbuf[1024];
        snprintf(pbuf, sizeof(pbuf), "%s", path);
        char *token = strtok(pbuf, ":");
        while (token) {
            char cand[512];
            snprintf(cand, sizeof(cand), "%s/xray", token);
            if (access(cand, X_OK) == 0) {
                snprintf(mgr->xray_bin, sizeof(mgr->xray_bin), "%.255s", cand);
                return mgr->xray_bin;
            }
            token = strtok(NULL, ":");
        }
    }

    snprintf(mgr->xray_bin, sizeof(mgr->xray_bin), "xray");
    return mgr->xray_bin;
}

int run_cmd(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static int run_privileged(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    if (geteuid() == 0) {
        return run_cmd(argv);
    }
    const char *pcmd[32];
    int idx = 0;
    if (access("/usr/bin/doas", X_OK) == 0) {
        pcmd[idx++] = "doas";
    } else {
        pcmd[idx++] = "sudo";
    }
    for (int i = 0; argv[i] && idx < 30; i++) {
        pcmd[idx++] = argv[i];
    }
    pcmd[idx] = NULL;
    return run_cmd(pcmd);
}

static int run_priv(const char *arg0, ...) {
    const char *argv[32];
    argv[0] = arg0;
    va_list ap;
    va_start(ap, arg0);
    int i = 1;
    const char *a;
    while ((a = va_arg(ap, const char *)) != NULL && i < 30) {
        argv[i++] = a;
    }
    va_end(ap);
    argv[i] = NULL;
    return run_privileged(argv);
}

static int run_cmd_read(const char *const argv[], char *buf, size_t buf_len) {
    if (!argv || !argv[0] || !buf || buf_len == 0) return -1;
    buf[0] = '\0';
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t total = 0;
    ssize_t n;
    while ((n = read(pipefd[0], buf + total, buf_len - 1 - total)) > 0) {
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(pipefd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* --- Direct Kernel Netlink Helpers --- */

static int netlink_talk(struct nlmsghdr *n) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -errno;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    n->nlmsg_seq = 1;
    n->nlmsg_pid = 0;

    struct iovec iov = { .iov_base = n, .iov_len = n->nlmsg_len };
    struct msghdr msg = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    if (sendmsg(fd, &msg, 0) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    char buf[4096];
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    ssize_t len = recvmsg(fd, &msg, 0);
    close(fd);
    if (len < 0) return -errno;

    for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len)) {
        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
            return err->error;
        }
        if (h->nlmsg_type == NLMSG_DONE) {
            return 0;
        }
    }
    return 0;
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen) {
    size_t len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) return -1;
    struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen > 0 && data) {
        memcpy(RTA_DATA(rta), data, alen);
    }
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

static int netlink_link_up(const char *dev, bool up) {
    unsigned int ifindex = if_nametoindex(dev);
    if (ifindex == 0) return -ENODEV;

    struct {
        struct nlmsghdr n;
        struct ifinfomsg ifi;
    } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = RTM_NEWLINK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = (int)ifindex;
    req.ifi.ifi_change = IFF_UP;
    req.ifi.ifi_flags = up ? IFF_UP : 0;

    return netlink_talk(&req.n);
}

static int netlink_link_del(const char *dev) {
    unsigned int ifindex = if_nametoindex(dev);
    if (ifindex == 0) return -ENODEV;

    struct {
        struct nlmsghdr n;
        struct ifinfomsg ifi;
    } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = RTM_DELLINK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = (int)ifindex;

    return netlink_talk(&req.n);
}

static int netlink_addr_add(const char *dev, const char *cidr) {
    unsigned int ifindex = if_nametoindex(dev);
    if (ifindex == 0) return -ENODEV;

    char ip_str[64];
    snprintf(ip_str, sizeof(ip_str), "%s", cidr);
    char *slash = strchr(ip_str, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    struct in_addr in;
    if (inet_pton(AF_INET, ip_str, &in) != 1) return -EINVAL;

    struct {
        struct nlmsghdr n;
        struct ifaddrmsg ifa;
        char buf[256];
    } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    req.n.nlmsg_type = RTM_NEWADDR;
    req.ifa.ifa_family = AF_INET;
    req.ifa.ifa_prefixlen = (unsigned char)prefix;
    req.ifa.ifa_flags = IFA_F_PERMANENT;
    req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
    req.ifa.ifa_index = ifindex;

    addattr_l(&req.n, sizeof(req), IFA_LOCAL, &in.s_addr, sizeof(in.s_addr));
    addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &in.s_addr, sizeof(in.s_addr));

    return netlink_talk(&req.n);
}

static int netlink_route(bool add, const char *dst_cidr, const char *gw, const char *dev) {
    char ip_str[64];
    snprintf(ip_str, sizeof(ip_str), "%s", dst_cidr);
    char *slash = strchr(ip_str, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    struct in_addr dst_in;
    if (inet_pton(AF_INET, ip_str, &dst_in) != 1) return -EINVAL;

    struct in_addr gw_in;
    bool has_gw = false;
    if (gw && gw[0] != '\0') {
        if (inet_pton(AF_INET, gw, &gw_in) == 1) {
            has_gw = true;
        }
    }

    int ifindex = 0;
    if (dev && dev[0] != '\0') {
        ifindex = (int)if_nametoindex(dev);
    }

    struct {
        struct nlmsghdr n;
        struct rtmsg rtm;
        char buf[512];
    } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) {
        req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
        req.n.nlmsg_type = RTM_NEWROUTE;
    } else {
        req.n.nlmsg_type = RTM_DELROUTE;
    }
    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_BOOT;
    req.rtm.rtm_scope = has_gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    req.rtm.rtm_type = RTN_UNICAST;
    req.rtm.rtm_dst_len = (unsigned char)prefix;

    if (prefix > 0 || dst_in.s_addr != 0) {
        addattr_l(&req.n, sizeof(req), RTA_DST, &dst_in.s_addr, sizeof(dst_in.s_addr));
    }
    if (has_gw) {
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw_in.s_addr, sizeof(gw_in.s_addr));
    }
    if (ifindex > 0) {
        addattr_l(&req.n, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));
    }

    return netlink_talk(&req.n);
}

/* Helpers with seamless fallback to run_priv if unprivileged */
static void route_add(const char *dst, const char *gw, const char *dev) {
    int ret = netlink_route(true, dst, gw, dev);
    if (ret == -EPERM || ret == -EACCES) {
        if (gw && gw[0]) {
            run_priv("ip", "route", "add", dst, "via", gw, "dev", dev, NULL);
        } else {
            run_priv("ip", "route", "add", dst, "dev", dev, NULL);
        }
    }
}

static void route_del(const char *dst, const char *gw, const char *dev) {
    int ret = netlink_route(false, dst, gw, dev);
    if (ret == -EPERM || ret == -EACCES) {
        if (gw && gw[0]) {
            run_priv("ip", "route", "del", dst, "via", gw, "dev", dev, NULL);
        } else {
            run_priv("ip", "route", "del", dst, "dev", dev, NULL);
        }
    }
}

static void link_up(const char *dev) {
    int ret = netlink_link_up(dev, true);
    if (ret == -EPERM || ret == -EACCES) {
        run_priv("ip", "link", "set", "dev", dev, "up", NULL);
    }
}

static void link_down(const char *dev) {
    int ret = netlink_link_up(dev, false);
    if (ret == -EPERM || ret == -EACCES) {
        run_priv("ip", "link", "set", "dev", dev, "down", NULL);
    }
}

static void link_del(const char *dev) {
    int ret = netlink_link_del(dev);
    if (ret == -EPERM || ret == -EACCES) {
        run_priv("ip", "link", "del", "dev", dev, NULL);
    }
}

static void addr_add(const char *dev, const char *cidr) {
    int ret = netlink_addr_add(dev, cidr);
    if (ret == -EPERM || ret == -EACCES) {
        run_priv("ip", "addr", "add", cidr, "dev", dev, NULL);
    }
}

/* --- Atomic DNS Switch Helpers --- */

static int copy_file_posix(const char *src, const char *dst) {
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return -1;
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) {
        close(sfd);
        return -1;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        if (write(dfd, buf, (size_t)n) != n) {
            close(sfd);
            close(dfd);
            return -1;
        }
    }
    close(sfd);
    close(dfd);
    return 0;
}

static int write_dns_file_atomic(const char *target_path, const char *dns1, const char *dns2) {
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.psyche_tmp", target_path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }
    dprintf(fd, "nameserver %s\nnameserver %s\n", dns1, dns2);
    close(fd);

    if (rename(tmp_path, target_path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static void set_ipv6_disabled(int disabled) {
    int fd = open("/proc/sys/net/ipv6/conf/all/disable_ipv6", O_WRONLY);
    if (fd >= 0) {
        char val = disabled ? '1' : '0';
        ssize_t w = write(fd, &val, 1);
        (void)w;
        close(fd);
    } else {
        run_priv("sysctl", "-w", disabled ? "net.ipv6.conf.all.disable_ipv6=1" : "net.ipv6.conf.all.disable_ipv6=0", NULL);
    }
}

static int resolve_all_hosts(tun_manager_t *mgr, const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* IPv4 */
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(host, NULL, &hints, &res);
    if (status != 0 || !res) return -1;

    mgr->server_ip_count = 0;
    for (struct addrinfo *p = res; p != NULL && mgr->server_ip_count < 16; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        char ip[64];
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip));
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

static int find_default_route(char *gw, size_t gw_len, char *dev, size_t dev_len, const char *ignore_dev) {
    /* 1. Fast zero-process check: parse /proc/net/route */
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            while (fgets(line, sizeof(line), fp)) {
                char iface[32];
                unsigned long dest = 0, gate = 0, mask = 0;
                unsigned int flags = 0;
                int refcnt = 0, use = 0, metric = 0;
                if (sscanf(line, "%31s %lx %lx %x %d %d %d %lx",
                           iface, &dest, &gate, &flags, &refcnt, &use, &metric, &mask) >= 8) {
                    if (dest == 0 && mask == 0 && (flags & 0x2)) {
                        if (ignore_dev && strcmp(iface, ignore_dev) == 0) {
                            continue;
                        }
                        struct in_addr gaddr;
                        gaddr.s_addr = (in_addr_t)gate;
                        snprintf(gw, gw_len, "%s", inet_ntoa(gaddr));
                        snprintf(dev, dev_len, "%s", iface);
                        fclose(fp);
                        return 0;
                    }
                }
            }
        }
        fclose(fp);
    }

    /* 2. Fallback: run 'ip -4 route show default' */
    char out[1024];
    const char *const argv[] = {"ip", "-4", "route", "show", "default", NULL};
    if (run_cmd_read(argv, out, sizeof(out)) == 0) {
        char *via_pos = strstr(out, "via ");
        char *dev_pos = strstr(out, "dev ");
        if (via_pos) {
            via_pos += 4;
            char *sp = strchr(via_pos, ' ');
            if (sp) {
                size_t l = (size_t)(sp - via_pos);
                if (l >= gw_len) l = gw_len - 1;
                memcpy(gw, via_pos, l);
                gw[l] = '\0';
            }
        }
        if (dev_pos) {
            dev_pos += 4;
            char *sp = strchr(dev_pos, ' ');
            size_t l = sp ? (size_t)(sp - dev_pos) : strlen(dev_pos);
            while (l > 0 && (dev_pos[l-1] == '\r' || dev_pos[l-1] == '\n' || dev_pos[l-1] == ' ')) l--;
            if (l >= dev_len) l = dev_len - 1;
            memcpy(dev, dev_pos, l);
            dev[l] = '\0';
        }
        if (gw[0] && dev[0]) return 0;
    }

    return -1;
}

int tun_mgr_connect(tun_manager_t *mgr, const server_node_t *node) {
    if (!mgr || !node) return -1;
    if (mgr->status == TUN_STATUS_CONNECTED) {
        tun_mgr_disconnect(mgr);
    }

    mgr->status = TUN_STATUS_CONNECTING;
    snprintf(mgr->connected_name, sizeof(mgr->connected_name), "%s", node->name);
    mgr->error_msg[0] = '\0';

    /* 1. Resolve remote server address */
    if (resolve_all_hosts(mgr, node->address) != 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Failed to resolve host: %.100s", node->address);
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    /* 2. Discover default route (ignoring any existing tun interface) */
    if (find_default_route(mgr->orig_gw, sizeof(mgr->orig_gw), mgr->orig_dev, sizeof(mgr->orig_dev), mgr->tun_dev) != 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Could not determine default gateway/interface");
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    /* 3. Prepare node config with resolved IP (breaks circular DNS deadlock in Xray) */
    server_node_t effective_node = *node;
    snprintf(effective_node.address, sizeof(effective_node.address), "%s", mgr->server_ip);
    if (effective_node.sni[0] == '\0') {
        snprintf(effective_node.sni, sizeof(effective_node.sni), "%s", node->address);
    }
    if (mgr->fingerprint[0] != '\0') {
        snprintf(effective_node.fp, sizeof(effective_node.fp), "%s", mgr->fingerprint);
    }

    /* Write Xray configuration */
    if (xray_config_write_file(&effective_node, xray_config_path, mgr->tun_dev) != 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "Failed to write Xray config to %s", xray_config_path);
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    /* 4. Start Xray child process detached from TUI stdin/stdout */
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(mgr->error_msg, sizeof(mgr->error_msg), "fork() failed: %s", strerror(errno));
        mgr->status = TUN_STATUS_ERROR;
        return -1;
    }

    if (pid == 0) {
        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }

        int log_fd = open(xray_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
        setpgid(0, 0);

        execlp(mgr->xray_bin, mgr->xray_bin, "run", "-c", xray_config_path, (char *)NULL);
        _exit(127);
    }

    mgr->xray_pid = pid;

    /* 5. Wait for TUN device to be created by Xray */
    char sys_tun_path[128];
    snprintf(sys_tun_path, sizeof(sys_tun_path), "/sys/class/net/%s", mgr->tun_dev);

    bool dev_ready = false;
    for (int i = 0; i < 30; i++) {
        usleep(100000); /* 100ms */
        int child_status = 0;
        pid_t wp = waitpid(pid, &child_status, WNOHANG);
        if (wp == pid) {
            mgr->xray_pid = 0;
            char log_snippet[200] = {0};
            FILE *lf = fopen(xray_log_path, "r");
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

    /* 6. Configure network interface & routing with privilege elevation */
    tun_mgr_priv_elevate();

    link_up(mgr->tun_dev);
    addr_add(mgr->tun_dev, default_tun_ip);

    /* Direct routes to all server IPs via original gateway */
    for (int i = 0; i < mgr->server_ip_count; i++) {
        route_add(mgr->server_ips[i], mgr->orig_gw, mgr->orig_dev);
    }

    /* Route 0.0.0.0/1 and 128.0.0.0/1 through TUN */
    route_add("0.0.0.0/1", NULL, mgr->tun_dev);
    route_add("128.0.0.0/1", NULL, mgr->tun_dev);

    /* Route DNS servers through TUN */
    route_add(default_dns1, NULL, mgr->tun_dev);
    route_add(default_dns2, NULL, mgr->tun_dev);

    /* Atomic DNS switch */
    char resolved[PATH_MAX];
    const char *tgt = realpath("/etc/resolv.conf", resolved);
    snprintf(mgr->resolv_target, sizeof(mgr->resolv_target), "%s", tgt ? tgt : "/etc/resolv.conf");
    mgr->resolv_existed = (access(mgr->resolv_target, F_OK) == 0);

    if (mgr->resolv_existed) {
        if (copy_file_posix(mgr->resolv_target, resolv_bak_path) != 0) {
            run_priv("cp", mgr->resolv_target, resolv_bak_path, NULL);
        }
    }

    if (write_dns_file_atomic(mgr->resolv_target, default_dns1, default_dns2) != 0) {
        FILE *rfp = fopen(resolv_tmp_path, "w");
        if (rfp) {
            fprintf(rfp, "nameserver %s\nnameserver %s\n", default_dns1, default_dns2);
            fclose(rfp);
            run_priv("cp", resolv_tmp_path, mgr->resolv_target, NULL);
            unlink(resolv_tmp_path);
        }
    }

    /* Shield against IPv6 leaks if configured */
    if (shield_ipv6) {
        FILE *fp_v6 = fopen("/proc/sys/net/ipv6/conf/all/disable_ipv6", "r");
        if (fp_v6) {
            char v6_val = '0';
            if (fread(&v6_val, 1, 1, fp_v6) == 1 && v6_val == '0') {
                mgr->ipv6_was_enabled = true;
                set_ipv6_disabled(1);
            }
            fclose(fp_v6);
        }
    }

    tun_mgr_priv_drop();

    mgr->status = TUN_STATUS_CONNECTED;
    return 0;
}

int tun_mgr_disconnect(tun_manager_t *mgr) {
    if (!mgr) return -1;

    tun_mgr_priv_elevate();

    /* Delete routes */
    route_del("0.0.0.0/1", NULL, mgr->tun_dev);
    route_del("128.0.0.0/1", NULL, mgr->tun_dev);
    route_del(default_dns1, NULL, mgr->tun_dev);
    route_del(default_dns2, NULL, mgr->tun_dev);

    for (int i = 0; i < mgr->server_ip_count; i++) {
        route_del(mgr->server_ips[i], mgr->orig_gw, mgr->orig_dev);
    }
    mgr->server_ip_count = 0;

    /* Restore DNS */
    if (mgr->resolv_target[0] != '\0') {
        if (mgr->resolv_existed && access(resolv_bak_path, F_OK) == 0) {
            if (copy_file_posix(resolv_bak_path, mgr->resolv_target) == 0) {
                unlink(resolv_bak_path);
            } else {
                run_priv("cp", resolv_bak_path, mgr->resolv_target, NULL);
                unlink(resolv_bak_path);
            }
        } else if (!mgr->resolv_existed) {
            unlink(mgr->resolv_target);
        }
    } else if (access(resolv_bak_path, F_OK) == 0) {
        if (copy_file_posix(resolv_bak_path, "/etc/resolv.conf") == 0) {
            unlink(resolv_bak_path);
        } else {
            run_priv("cp", resolv_bak_path, "/etc/resolv.conf", NULL);
            unlink(resolv_bak_path);
        }
    }

    /* Restore IPv6 */
    if (mgr->ipv6_was_enabled) {
        set_ipv6_disabled(0);
        mgr->ipv6_was_enabled = false;
    }

    /* Bring down and delete interface */
    link_down(mgr->tun_dev);
    link_del(mgr->tun_dev);

    /* Terminate and cleanly reap Xray process */
    if (mgr->xray_pid > 0) {
        kill(mgr->xray_pid, SIGTERM);
        for (int i = 0; i < 20; i++) {
            usleep(50000); /* 50ms */
            int status = 0;
            pid_t wp = waitpid(mgr->xray_pid, &status, WNOHANG);
            if (wp == mgr->xray_pid || (wp < 0 && errno == ECHILD)) {
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

    unlink(xray_config_path);

    tun_mgr_priv_drop();

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
