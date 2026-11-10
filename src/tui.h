#ifndef TUI_H
#define TUI_H

#include "sub_parser.h"
#include "tun_mgr.h"
#include <stdbool.h>

typedef struct {
    int rows;
    int cols;
    int selected;
    int scroll_top;
    char search_query[64];
    bool in_search;
    bool in_input_url;
    char input_url[1024];
    size_t input_cursor;
    int *filtered_indices;
    size_t filtered_count;
    char status_msg[256];
} tui_state_t;

void tui_init(tui_state_t *tui);
void tui_cleanup(void);
void tui_raw_mode_enable(void);
void tui_raw_mode_disable(void);

void tui_update_size(tui_state_t *tui);
void tui_update_filter(tui_state_t *tui, const subscription_t *sub);
void tui_render(tui_state_t *tui, const subscription_t *sub, const tun_manager_t *tun);

// First-run setup screen — collects subscription URL, fetches nodes.
// Returns true on success (sub->url and nodes populated), false if user quit.
bool tui_first_run(tui_state_t *tui, subscription_t *sub);

// Returns true if should continue running, false to quit
bool tui_handle_input(tui_state_t *tui, subscription_t *sub, tun_manager_t *tun);

#endif // TUI_H
