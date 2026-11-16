#define _GNU_SOURCE
#include "config.h"
#include "sub_parser.h"
#include "tun_mgr.h"
#include "tui.h"
#include "ping.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <pwd.h>
#include <locale.h>

static tun_manager_t  g_tun;
static tui_state_t    g_tui;
static subscription_t g_sub;
static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void sigwinch_handler(int sig) {
    (void)sig;
    tui_update_size(&g_tui);
}

static void fatal_handler(int sig) {
    tui_raw_mode_disable();
    tun_mgr_cleanup(&g_tun);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, NULL);
    raise(sig);
}

static void get_config_dir(char *buf, size_t len) {
    const char *home = NULL;
    const char *s_uid = getenv("SUDO_UID");
    if (s_uid) {
        struct passwd *pw = getpwuid((uid_t)atoi(s_uid));
        if (pw) home = pw->pw_dir;
    }
    if (!home) home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) home = "/tmp";
    snprintf(buf, len, "%s/.config/psyche", home);
}

static void ensure_config_dir(const char *dir) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    char *slash = strrchr(tmp, '/');
    if (slash) {
        *slash = '\0';
        mkdir(tmp, 0755);
        *slash = '/';
    }
    mkdir(tmp, 0755);
}

static void load_app_config(char *url, size_t url_len, char *tun_dev, size_t dev_len, char *fp, size_t fp_len) {
    char dir[512], cfg_file[1024];
    get_config_dir(dir, sizeof(dir));
    snprintf(cfg_file, sizeof(cfg_file), "%s/config.json", dir);

    int fd = open(cfg_file, O_RDONLY);
    if (fd < 0) return;
    char buf[2048];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return;
    buf[r] = '\0';

    if (url && url[0] == '\0') json_get_str(buf, "subscription_url", url, url_len);
    if (tun_dev && tun_dev[0] == '\0') json_get_str(buf, "tun_dev", tun_dev, dev_len);
    if (fp && fp[0] == '\0') json_get_str(buf, "fingerprint", fp, fp_len);
}

static void save_app_config(const char *url, const char *tun_dev, const char *fp) {
    char dir[512], cfg_file[1024];
    get_config_dir(dir, sizeof(dir));
    ensure_config_dir(dir);
    snprintf(cfg_file, sizeof(cfg_file), "%s/config.json", dir);

    int fd = open(cfg_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    dprintf(fd, "{\n  \"subscription_url\": \"%s\",\n  \"tun_dev\": \"%s\",\n  \"fingerprint\": \"%s\"\n}\n",
            url ? url : "", tun_dev ? tun_dev : "", fp ? fp : "");
    close(fd);
}

static void print_usage(const char *prog) {
    printf("Psyche - Minimalist Xray TUN VPN Client for Linux\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -u, --url <URL>       Load subscription from URL\n");
    printf("  -f, --file <FILE>     Load subscription from local file\n");
    printf("  -d, --dev <NAME>      Set TUN interface name (default: %s)\n", default_tun_dev);
    printf("  --fp <PROFILE>        Set TLS fingerprint (chrome, randomized, firefox, safari, ios)\n");
    printf("  -h, --help            Show this help message\n\n");
    printf("Keybindings:\n");
    printf("  Enter                 Connect / Disconnect selected node\n");
    printf("  j / k, Up / Down      Navigate node list\n");
    printf("  g / G, Home / End     Jump to top / bottom\n");
    printf("  d                     Disconnect VPN\n");
    printf("  f                     Cycle TLS fingerprint\n");
    printf("  u                     Update subscription from URL\n");
    printf("  s                     Change subscription URL\n");
    printf("  p                     Ping selected node\n");
    printf("  P                     Ping all nodes in parallel\n");
    printf("  o                     Sort nodes by latency (asc/desc/orig)\n");
    printf("  /                     Filter / search nodes\n");
    printf("  Esc                   Clear search filter\n");
    printf("  q                     Quit\n");
}

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    tun_mgr_priv_init();

    char cli_url[1024] = {0};
    char cli_file[512] = {0};
    char cli_dev[32] = {0};
    char cli_fp[32] = {0};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--url") == 0) {
            if (i + 1 < argc) snprintf(cli_url, sizeof(cli_url), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if (i + 1 < argc) snprintf(cli_file, sizeof(cli_file), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dev") == 0) {
            if (i + 1 < argc) snprintf(cli_dev, sizeof(cli_dev), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--fp") == 0 || strcmp(argv[i], "-fp") == 0) {
            if (i + 1 < argc) snprintf(cli_fp, sizeof(cli_fp), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    /* Load saved settings if not provided on CLI */
    load_app_config(cli_url, sizeof(cli_url), cli_dev, sizeof(cli_dev), cli_fp, sizeof(cli_fp));

    /* Initialize systems */
    sub_init(&g_sub);
    tun_mgr_init(&g_tun);
    if (cli_dev[0]) {
        snprintf(g_tun.tun_dev, sizeof(g_tun.tun_dev), "%s", cli_dev);
    }
    if (cli_fp[0]) {
        snprintf(g_tun.fingerprint, sizeof(g_tun.fingerprint), "%s", cli_fp);
    }
    tui_init(&g_tui);

    /* Setup signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    struct sigaction sa_winch;
    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = sigwinch_handler;
    sigaction(SIGWINCH, &sa_winch, NULL);

    /* Safety fatal handlers */
    struct sigaction sa_fatal;
    memset(&sa_fatal, 0, sizeof(sa_fatal));
    sa_fatal.sa_handler = fatal_handler;
    sigaction(SIGSEGV, &sa_fatal, NULL);
    sigaction(SIGABRT, &sa_fatal, NULL);
    sigaction(SIGBUS, &sa_fatal, NULL);
    sigaction(SIGFPE, &sa_fatal, NULL);
    sigaction(SIGILL, &sa_fatal, NULL);

    /* Cache file path */
    char dir[512], cache_file[1024];
    get_config_dir(dir, sizeof(dir));
    ensure_config_dir(dir);
    snprintf(cache_file, sizeof(cache_file), "%s/cached_nodes.txt", dir);

    /* Load nodes — or show first-run setup if no source is configured */
    if (cli_url[0] == '\0' && cli_file[0] == '\0') {
        if (!tui_first_run(&g_tui, &g_sub)) {
            tui_cleanup();
            sub_free(&g_sub);
            return 0;
        }
        save_app_config(g_sub.url, g_tun.tun_dev, g_tun.fingerprint);
        sub_save_cache(&g_sub, cache_file);
    } else if (cli_file[0]) {
        sub_load_file(&g_sub, cli_file);
    } else if (cli_url[0]) {
        snprintf(g_sub.url, sizeof(g_sub.url), "%s", cli_url);
        if (sub_load_cache(&g_sub, cache_file) <= 0) {
            sub_fetch_url(&g_sub, cli_url);
            sub_save_cache(&g_sub, cache_file);
        }
    }

    tui_update_filter(&g_tui, &g_sub);

    /* Check privileges */
    if (!tun_mgr_has_net_admin()) {
        snprintf(g_tui.status_msg, sizeof(g_tui.status_msg),
                 "no net_admin — sudo/doas will be invoked for tun setup");
    }

    /* Enable Raw Mode and enter event loop */
    tui_raw_mode_enable();

    while (g_running) {
        tui_render(&g_tui, &g_sub, &g_tun);
        if (!tui_handle_input(&g_tui, &g_sub, &g_tun)) {
            break;
        }
    }

    /* Teardown */
    tui_raw_mode_disable();
    tun_mgr_cleanup(&g_tun);

    /* Save cache and config */
    if (g_sub.count > 0) {
        sub_save_cache(&g_sub, cache_file);
    }
    save_app_config(g_sub.url, g_tun.tun_dev, g_tun.fingerprint);

    sub_free(&g_sub);
    if (g_tui.filtered_indices) {
        free(g_tui.filtered_indices);
    }

    printf("\nPsyche terminated cleanly.\n");
    return 0;
}
