#ifndef CONFIG_DEF_H
#define CONFIG_DEF_H

#if defined(__GNUC__) || defined(__clang__)
#define PSYCHE_UNUSED __attribute__((unused))
#else
#define PSYCHE_UNUSED
#endif

/* Default TUN device and local proxy ports */
static const char default_tun_dev[]  = "psyche0";
static const int  default_socks_port = 10808;
static const int  default_http_port  = 10809;
static const char default_tun_ip[]   = "172.19.0.1/30";

/* Timeouts */
static const int  ping_timeout_ms    = 1500;
static const int  http_timeout_s     = 15;

/* Runtime paths */
static const char xray_config_path[] = "/tmp/psyche_xray.json";
static const char xray_log_path[]    = "/tmp/psyche_xray.log";
static const char resolv_bak_path[]  = "/tmp/psyche_resolv.bak";
static const char resolv_tmp_path[]  = "/tmp/psyche_resolv.new";

/* DNS fallback servers */
static const char default_dns1[]     = "1.1.1.1";
static const char default_dns2[]     = "8.8.8.8";
static const char default_doh[]      = "https://1.1.1.1/dns-query";

/* Supported TLS/uTLS fingerprint profiles for Reality and TLS outbounds */
static const char *fingerprints[] PSYCHE_UNUSED = {
    "chrome",
    "randomized",
    "firefox",
    "safari",
    "ios"
};
#define NUM_FINGERPRINTS ((int)(sizeof(fingerprints) / sizeof(fingerprints[0])))

/* Keybindings */
static const char key_quit        = 'q';
static const char key_up          = 'k';
static const char key_down        = 'j';
static const char key_top         = 'g';
static const char key_bottom      = 'G';
static const char key_search      = '/';
static const char key_sort        = 'o';
static const char key_url         = 's';
static const char key_sync        = 'u';
static const char key_disconnect  = 'd';
static const char key_fingerprint = 'f';
static const char key_ping        = 'p';
static const char key_ping_all    = 'P';

/* Visual and atmospheric prompts */
static const char brand_name[]       = "psyche";
static const char boot_phrase[]      = "present day. present time.";
static const char boot_prompt[]      = "enter subscription url.";
static const char glitch_chars[]     = ".:;~|+=<>_-/\\^*#@!?%&";

/* Privacy: 1 to temporarily disable IPv6 during tunnel link to prevent leaks */
static const int  shield_ipv6        = 1;

#endif /* CONFIG_DEF_H */
