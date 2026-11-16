#ifndef TUI_H
#define TUI_H

#include "sub_parser.h"
#include "tun_mgr.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    SORT_DEFAULT = 0,
    SORT_PING_ASC = 1,
    SORT_PING_DESC = 2
} sort_mode_t;

typedef struct {
    int rows;
    int cols;
    int selected;
    int scroll_top;
    char search_query[128];
    bool in_search;
    bool in_input_url;
    char input_url[1024];
    size_t input_cursor;
    int *filtered_indices;
    size_t filtered_count;
    char status_msg[256];
    sort_mode_t sort_mode;
} tui_state_t;

void tui_init(tui_state_t *tui);
void tui_cleanup(void);
void tui_raw_mode_enable(void);
void tui_raw_mode_disable(void);

void tui_update_size(tui_state_t *tui);
void tui_update_filter(tui_state_t *tui, const subscription_t *sub);
void tui_render(tui_state_t *tui, const subscription_t *sub, const tun_manager_t *tun);

/* UTF-8 case-insensitive substring search */
const char *utf8_strcasestr(const char *haystack, const char *needle);

/* First-run setup screen */
bool tui_first_run(tui_state_t *tui, subscription_t *sub);

/* Event loop input handler (returns false to quit) */
bool tui_handle_input(tui_state_t *tui, subscription_t *sub, tun_manager_t *tun);

#endif /* TUI_H */
