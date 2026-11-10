#define _GNU_SOURCE
#include "sub_parser.h"
#include "tun_mgr.h"
#include "tui.h"
#include "cJSON.h"

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
#include <sys/stat.h>
#include <pwd.h>

static tun_manager_t g_tun;
static tui_state_t   g_tui;
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

static void get_config_dir(char *buf, size_t len) {
    const char *home = getenv("HOME");
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
    // Create ~/.config if needed
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

    FILE *f = fopen(cfg_file, "r");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return; }

    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return; }

    size_t r = fread(buf, 1, sz, f);
    buf[r] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return;

    cJSON *u = cJSON_GetObjectItem(root, "subscription_url");
    if (u && cJSON_IsString(u) && url[0] == '\0') {
        snprintf(url, url_len, "%s", u->valuestring);
    }

    cJSON *d = cJSON_GetObjectItem(root, "tun_dev");
    if (d && cJSON_IsString(d) && tun_dev[0] == '\0') {
        snprintf(tun_dev, dev_len, "%s", d->valuestring);
    }

    cJSON *fitem = cJSON_GetObjectItem(root, "fingerprint");
    if (fitem && cJSON_IsString(fitem) && fp && fp[0] == '\0') {
        snprintf(fp, fp_len, "%s", fitem->valuestring);
    }

    cJSON_Delete(root);
}

static void save_app_config(const char *url, const char *tun_dev, const char *fp) {
    char dir[512], cfg_file[1024];
    get_config_dir(dir, sizeof(dir));
    ensure_config_dir(dir);
    snprintf(cfg_file, sizeof(cfg_file), "%s/config.json", dir);

    cJSON *root = cJSON_CreateObject();
    if (url && url[0]) cJSON_AddStringToObject(root, "subscription_url", url);
    if (tun_dev && tun_dev[0]) cJSON_AddStringToObject(root, "tun_dev", tun_dev);
    if (fp && fp[0]) cJSON_AddStringToObject(root, "fingerprint", fp);

    char *printed = cJSON_Print(root);
    cJSON_Delete(root);
    if (!printed) return;

    FILE *f = fopen(cfg_file, "w");
    if (f) {
        fputs(printed, f);
        fclose(f);
    }
    free(printed);
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
    printf("  d                     Disconnect VPN\n");
    printf("  f                     Cycle TLS fingerprint (chrome, randomized, firefox...)\n");
    printf("  u                     Update subscription from URL\n");
    printf("  s                     Change subscription URL\n");
    printf("  p                     Ping selected node\n");
    printf("  /                     Filter / search nodes\n");
    printf("  Esc                   Clear search filter\n");
    printf("  q                     Quit\n");
}

int main(int argc, char **argv) {
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

    // Load saved settings if not provided on CLI
    load_app_config(cli_url, sizeof(cli_url), cli_dev, sizeof(cli_dev), cli_fp, sizeof(cli_fp));

    // Initialize systems
    sub_init(&g_sub);
    tun_mgr_init(&g_tun);
    if (cli_dev[0]) {
        snprintf(g_tun.tun_dev, sizeof(g_tun.tun_dev), "%s", cli_dev);
    }
    if (cli_fp[0]) {
        snprintf(g_tun.fingerprint, sizeof(g_tun.fingerprint), "%s", cli_fp);
    }
    tui_init(&g_tui);

    // Setup signal handlers
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

    // Cache file path
    char dir[512], cache_file[1024];
    get_config_dir(dir, sizeof(dir));
    ensure_config_dir(dir);
    snprintf(cache_file, sizeof(cache_file), "%s/cached_nodes.txt", dir);

    // Load nodes — or show first-run setup if no source is configured
    if (cli_url[0] == '\0' && cli_file[0] == '\0') {
        // No subscription URL from CLI or config — first run
        if (!tui_first_run(&g_tui, &g_sub)) {
            tui_cleanup();
            sub_free(&g_sub);
            return 0;
        }
        // tui_first_run populated g_sub.url and fetched nodes
        save_app_config(g_sub.url, g_tun.tun_dev, g_tun.fingerprint);
        sub_save_cache(&g_sub, cache_file);
    } else if (cli_file[0]) {
        sub_load_file(&g_sub, cli_file);
    } else if (cli_url[0]) {
        snprintf(g_sub.url, sizeof(g_sub.url), "%s", cli_url);
        // Try cache first for instant launch
        if (sub_load_cache(&g_sub, cache_file) <= 0) {
            // Fetch from URL if cache is empty
            sub_fetch_url(&g_sub, cli_url);
            sub_save_cache(&g_sub, cache_file);
        }
    }

    tui_update_filter(&g_tui, &g_sub);

    // Check privileges & show hint
    if (!tun_mgr_is_root()) {
        snprintf(g_tui.status_msg, sizeof(g_tui.status_msg),
                 "no root — sudo/doas will be invoked for tun setup");
    }

    // Enable Raw Mode and enter event loop
    tui_raw_mode_enable();

    while (g_running) {
        tui_render(&g_tui, &g_sub, &g_tun);
        if (!tui_handle_input(&g_tui, &g_sub, &g_tun)) {
            break;
        }
    }

    // Teardown
    tui_raw_mode_disable();
    tun_mgr_cleanup(&g_tun);

    // Save cache and config
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
