#ifndef CONFIG_DEF_H
#define CONFIG_DEF_H

/* Default TUN device and local proxy ports */
static const char default_tun_dev[]  = "psyche0";
static const int  default_socks_port = 10808;
static const int  default_http_port  = 10809;

/* TCP ping probe timeout in milliseconds */
static const int  ping_timeout_ms    = 1500;

/* Supported TLS/uTLS fingerprint profiles for Reality and TLS outbounds */
static const char *fingerprints[] = {
    "chrome",
    "randomized",
    "firefox",
    "safari",
    "ios"
};
#define NUM_FINGERPRINTS ((int)(sizeof(fingerprints) / sizeof(fingerprints[0])))

/* Visual and atmospheric prompts */
static const char brand_name[]       = "psyche";
static const char boot_phrase[]      = "present day. present time.";
static const char boot_prompt[]      = "enter subscription url.";
static const char glitch_chars[]     = ".:;~|+=<>_-/\\^*#@!?%&";

/* Privacy: 1 to temporarily disable IPv6 during tunnel link to prevent leaks */
static const int  shield_ipv6        = 1;

#endif /* CONFIG_DEF_H */
