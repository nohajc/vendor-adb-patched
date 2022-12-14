/* debugfs/extent_cmds.c - automatically generated from debugfs/extent_cmds.ct */
#include <ss/ss.h>

static char const * const ssu00001[] = {
"current_node",
    "current",
    (char const *)0
};
extern void do_current_node __SS_PROTO;
static char const * const ssu00002[] = {
"root_node",
    "root",
    (char const *)0
};
extern void do_root_node __SS_PROTO;
static char const * const ssu00003[] = {
"last_leaf",
    (char const *)0
};
extern void do_last_leaf __SS_PROTO;
static char const * const ssu00004[] = {
"first_sibling",
    "first_sib",
    (char const *)0
};
extern void do_first_sib __SS_PROTO;
static char const * const ssu00005[] = {
"last_sibling",
    "last_sib",
    (char const *)0
};
extern void do_last_sib __SS_PROTO;
static char const * const ssu00006[] = {
"next_sibling",
    "next_sib",
    "ns",
    (char const *)0
};
extern void do_next_sib __SS_PROTO;
static char const * const ssu00007[] = {
"prev_sibling",
    "prev_sib",
    "ps",
    (char const *)0
};
extern void do_prev_sib __SS_PROTO;
static char const * const ssu00008[] = {
"next_leaf",
    "nl",
    (char const *)0
};
extern void do_next_leaf __SS_PROTO;
static char const * const ssu00009[] = {
"prev_leaf",
    "pl",
    (char const *)0
};
extern void do_prev_leaf __SS_PROTO;
static char const * const ssu00010[] = {
"next",
    "n",
    (char const *)0
};
extern void do_next __SS_PROTO;
static char const * const ssu00011[] = {
"previous",
    "prev",
    "p",
    (char const *)0
};
extern void do_prev __SS_PROTO;
static char const * const ssu00012[] = {
"up_node",
    "up",
    "u",
    (char const *)0
};
extern void do_up __SS_PROTO;
static char const * const ssu00013[] = {
"down_node",
    "down",
    "d",
    (char const *)0
};
extern void do_down __SS_PROTO;
static char const * const ssu00014[] = {
"delete_node",
    "delete",
    (char const *)0
};
extern void do_delete_node __SS_PROTO;
static char const * const ssu00015[] = {
"insert_node",
    "insert",
    (char const *)0
};
extern void do_insert_node __SS_PROTO;
static char const * const ssu00016[] = {
"split_node",
    "split",
    (char const *)0
};
extern void do_split_node __SS_PROTO;
static char const * const ssu00017[] = {
"fix_parents",
    "fixp",
    (char const *)0
};
extern void do_fix_parents __SS_PROTO;
static char const * const ssu00018[] = {
"set_bmap",
    (char const *)0
};
extern void do_set_bmap __SS_PROTO;
static char const * const ssu00019[] = {
"replace_node",
    "replace",
    (char const *)0
};
extern void do_replace_node __SS_PROTO;
static char const * const ssu00020[] = {
"print_all",
    "all",
    (char const *)0
};
extern void do_print_all __SS_PROTO;
static char const * const ssu00021[] = {
"goto_block",
    "goto",
    (char const *)0
};
extern void do_goto_block __SS_PROTO;
static char const * const ssu00022[] = {
"info",
    (char const *)0
};
extern void do_info __SS_PROTO;
static char const * const ssu00023[] = {
"extent_close",
    "ec",
    (char const *)0
};
extern void do_extent_close __SS_PROTO;
static ss_request_entry ssu00024[] = {
    { ssu00001,
      do_current_node,
      "Current extent node",
      0 },
    { ssu00002,
      do_root_node,
      "Goto root extent",
      0 },
    { ssu00003,
      do_last_leaf,
      "Goto last leaf",
      0 },
    { ssu00004,
      do_first_sib,
      "Goto first sibling",
      0 },
    { ssu00005,
      do_last_sib,
      "Goto last sibling",
      0 },
    { ssu00006,
      do_next_sib,
      "Goto next sibling",
      0 },
    { ssu00007,
      do_prev_sib,
      "Goto previous sibling",
      0 },
    { ssu00008,
      do_next_leaf,
      "Goto next leaf",
      0 },
    { ssu00009,
      do_prev_leaf,
      "Goto previous leaf",
      0 },
    { ssu00010,
      do_next,
      "Goto next node",
      0 },
    { ssu00011,
      do_prev,
      "Goto previous node",
      0 },
    { ssu00012,
      do_up,
      "Up node",
      0 },
    { ssu00013,
      do_down,
      "Down node",
      0 },
    { ssu00014,
      do_delete_node,
      "Delete node",
      0 },
    { ssu00015,
      do_insert_node,
      "Insert node",
      0 },
    { ssu00016,
      do_split_node,
      "Split node",
      0 },
    { ssu00017,
      do_fix_parents,
      "Fix parents",
      0 },
    { ssu00018,
      do_set_bmap,
      "Set block mapping",
      0 },
    { ssu00019,
      do_replace_node,
      "Insert node",
      0 },
    { ssu00020,
      do_print_all,
      "Iterate over all nodes and print them",
      0 },
    { ssu00021,
      do_goto_block,
      "Goto extent containing specified block",
      0 },
    { ssu00022,
      do_info,
      "Print extent info",
      0 },
    { ssu00023,
      do_extent_close,
      "Close extent handle",
      0 },
    { 0, 0, 0, 0 }
};

ss_request_table extent_cmds = { 2, ssu00024 };
