/* debugfs/debug_cmds.c - automatically generated from debugfs/debug_cmds.ct */
#include <ss/ss.h>

static char const * const ssu00001[] = {
"show_debugfs_params",
    "params",
    (char const *)0
};
extern void do_show_debugfs_params __SS_PROTO;
static char const * const ssu00002[] = {
"open_filesys",
    "open",
    (char const *)0
};
extern void do_open_filesys __SS_PROTO;
static char const * const ssu00003[] = {
"close_filesys",
    "close",
    (char const *)0
};
extern void do_close_filesys __SS_PROTO;
static char const * const ssu00004[] = {
"freefrag",
    "e2freefrag",
    (char const *)0
};
extern void do_freefrag __SS_PROTO;
static char const * const ssu00005[] = {
"feature",
    "features",
    (char const *)0
};
extern void do_features __SS_PROTO;
static char const * const ssu00006[] = {
"dirty_filesys",
    "dirty",
    (char const *)0
};
extern void do_dirty_filesys __SS_PROTO;
static char const * const ssu00007[] = {
"init_filesys",
    (char const *)0
};
extern void do_init_filesys __SS_PROTO;
static char const * const ssu00008[] = {
"show_super_stats",
    "stats",
    (char const *)0
};
extern void do_show_super_stats __SS_PROTO;
static char const * const ssu00009[] = {
"ncheck",
    (char const *)0
};
extern void do_ncheck __SS_PROTO;
static char const * const ssu00010[] = {
"icheck",
    (char const *)0
};
extern void do_icheck __SS_PROTO;
static char const * const ssu00011[] = {
"change_root_directory",
    "chroot",
    (char const *)0
};
extern void do_chroot __SS_PROTO;
static char const * const ssu00012[] = {
"change_working_directory",
    "cd",
    (char const *)0
};
extern void do_change_working_dir __SS_PROTO;
static char const * const ssu00013[] = {
"list_directory",
    "ls",
    (char const *)0
};
extern void do_list_dir __SS_PROTO;
static char const * const ssu00014[] = {
"show_inode_info",
    "stat",
    (char const *)0
};
extern void do_stat __SS_PROTO;
static char const * const ssu00015[] = {
"dump_extents",
    "extents",
    "ex",
    (char const *)0
};
extern void do_dump_extents __SS_PROTO;
static char const * const ssu00016[] = {
"blocks",
    (char const *)0
};
extern void do_blocks __SS_PROTO;
static char const * const ssu00017[] = {
"filefrag",
    (char const *)0
};
extern void do_filefrag __SS_PROTO;
static char const * const ssu00018[] = {
"link",
    "ln",
    (char const *)0
};
extern void do_link __SS_PROTO;
static char const * const ssu00019[] = {
"unlink",
    (char const *)0
};
extern void do_unlink __SS_PROTO;
static char const * const ssu00020[] = {
"mkdir",
    (char const *)0
};
extern void do_mkdir __SS_PROTO;
static char const * const ssu00021[] = {
"rmdir",
    (char const *)0
};
extern void do_rmdir __SS_PROTO;
static char const * const ssu00022[] = {
"rm",
    (char const *)0
};
extern void do_rm __SS_PROTO;
static char const * const ssu00023[] = {
"kill_file",
    (char const *)0
};
extern void do_kill_file __SS_PROTO;
static char const * const ssu00024[] = {
"copy_inode",
    (char const *)0
};
extern void do_copy_inode __SS_PROTO;
static char const * const ssu00025[] = {
"clri",
    (char const *)0
};
extern void do_clri __SS_PROTO;
static char const * const ssu00026[] = {
"freei",
    (char const *)0
};
extern void do_freei __SS_PROTO;
static char const * const ssu00027[] = {
"seti",
    (char const *)0
};
extern void do_seti __SS_PROTO;
static char const * const ssu00028[] = {
"testi",
    (char const *)0
};
extern void do_testi __SS_PROTO;
static char const * const ssu00029[] = {
"freeb",
    (char const *)0
};
extern void do_freeb __SS_PROTO;
static char const * const ssu00030[] = {
"setb",
    (char const *)0
};
extern void do_setb __SS_PROTO;
static char const * const ssu00031[] = {
"testb",
    (char const *)0
};
extern void do_testb __SS_PROTO;
static char const * const ssu00032[] = {
"modify_inode",
    "mi",
    (char const *)0
};
extern void do_modify_inode __SS_PROTO;
static char const * const ssu00033[] = {
"find_free_block",
    "ffb",
    (char const *)0
};
extern void do_find_free_block __SS_PROTO;
static char const * const ssu00034[] = {
"find_free_inode",
    "ffi",
    (char const *)0
};
extern void do_find_free_inode __SS_PROTO;
static char const * const ssu00035[] = {
"print_working_directory",
    "pwd",
    (char const *)0
};
extern void do_print_working_directory __SS_PROTO;
static char const * const ssu00036[] = {
"expand_dir",
    "expand",
    (char const *)0
};
extern void do_expand_dir __SS_PROTO;
static char const * const ssu00037[] = {
"mknod",
    (char const *)0
};
extern void do_mknod __SS_PROTO;
static char const * const ssu00038[] = {
"list_deleted_inodes",
    "lsdel",
    (char const *)0
};
extern void do_lsdel __SS_PROTO;
static char const * const ssu00039[] = {
"undelete",
    "undel",
    (char const *)0
};
extern void do_undel __SS_PROTO;
static char const * const ssu00040[] = {
"write",
    (char const *)0
};
extern void do_write __SS_PROTO;
static char const * const ssu00041[] = {
"dump_inode",
    "dump",
    (char const *)0
};
extern void do_dump __SS_PROTO;
static char const * const ssu00042[] = {
"cat",
    (char const *)0
};
extern void do_cat __SS_PROTO;
static char const * const ssu00043[] = {
"lcd",
    (char const *)0
};
extern void do_lcd __SS_PROTO;
static char const * const ssu00044[] = {
"rdump",
    (char const *)0
};
extern void do_rdump __SS_PROTO;
static char const * const ssu00045[] = {
"set_super_value",
    "ssv",
    (char const *)0
};
extern void do_set_super __SS_PROTO;
static char const * const ssu00046[] = {
"set_inode_field",
    "sif",
    (char const *)0
};
extern void do_set_inode __SS_PROTO;
static char const * const ssu00047[] = {
"set_block_group",
    "set_bg",
    (char const *)0
};
extern void do_set_block_group_descriptor __SS_PROTO;
static char const * const ssu00048[] = {
"logdump",
    (char const *)0
};
extern void do_logdump __SS_PROTO;
static char const * const ssu00049[] = {
"htree_dump",
    "htree",
    (char const *)0
};
extern void do_htree_dump __SS_PROTO;
static char const * const ssu00050[] = {
"dx_hash",
    "hash",
    (char const *)0
};
extern void do_dx_hash __SS_PROTO;
static char const * const ssu00051[] = {
"dirsearch",
    (char const *)0
};
extern void do_dirsearch __SS_PROTO;
static char const * const ssu00052[] = {
"bmap",
    (char const *)0
};
extern void do_bmap __SS_PROTO;
static char const * const ssu00053[] = {
"fallocate",
    (char const *)0
};
extern void do_fallocate __SS_PROTO;
static char const * const ssu00054[] = {
"punch",
    "truncate",
    (char const *)0
};
extern void do_punch __SS_PROTO;
static char const * const ssu00055[] = {
"symlink",
    (char const *)0
};
extern void do_symlink __SS_PROTO;
static char const * const ssu00056[] = {
"imap",
    (char const *)0
};
extern void do_imap __SS_PROTO;
static char const * const ssu00057[] = {
"dump_unused",
    (char const *)0
};
extern void do_dump_unused __SS_PROTO;
static char const * const ssu00058[] = {
"set_current_time",
    (char const *)0
};
extern void do_set_current_time __SS_PROTO;
static char const * const ssu00059[] = {
"supported_features",
    (char const *)0
};
extern void do_supported_features __SS_PROTO;
static char const * const ssu00060[] = {
"dump_mmp",
    (char const *)0
};
extern void do_dump_mmp __SS_PROTO;
static char const * const ssu00061[] = {
"set_mmp_value",
    "smmp",
    (char const *)0
};
extern void do_set_mmp_value __SS_PROTO;
static char const * const ssu00062[] = {
"extent_open",
    "eo",
    (char const *)0
};
extern void do_extent_open __SS_PROTO;
static char const * const ssu00063[] = {
"zap_block",
    "zap",
    (char const *)0
};
extern void do_zap_block __SS_PROTO;
static char const * const ssu00064[] = {
"block_dump",
    "bdump",
    "bd",
    (char const *)0
};
extern void do_block_dump __SS_PROTO;
static char const * const ssu00065[] = {
"ea_list",
    (char const *)0
};
extern void do_list_xattr __SS_PROTO;
static char const * const ssu00066[] = {
"ea_get",
    (char const *)0
};
extern void do_get_xattr __SS_PROTO;
static char const * const ssu00067[] = {
"ea_set",
    (char const *)0
};
extern void do_set_xattr __SS_PROTO;
static char const * const ssu00068[] = {
"ea_rm",
    (char const *)0
};
extern void do_rm_xattr __SS_PROTO;
static char const * const ssu00069[] = {
"list_quota",
    "lq",
    (char const *)0
};
extern void do_list_quota __SS_PROTO;
static char const * const ssu00070[] = {
"get_quota",
    "gq",
    (char const *)0
};
extern void do_get_quota __SS_PROTO;
static char const * const ssu00071[] = {
"inode_dump",
    "idump",
    "id",
    (char const *)0
};
extern void do_idump __SS_PROTO;
static char const * const ssu00072[] = {
"journal_open",
    "jo",
    (char const *)0
};
extern void do_journal_open __SS_PROTO;
static char const * const ssu00073[] = {
"journal_close",
    "jc",
    (char const *)0
};
extern void do_journal_close __SS_PROTO;
static char const * const ssu00074[] = {
"journal_write",
    "jw",
    (char const *)0
};
extern void do_journal_write __SS_PROTO;
static char const * const ssu00075[] = {
"journal_run",
    "jr",
    (char const *)0
};
extern void do_journal_run __SS_PROTO;
static ss_request_entry ssu00076[] = {
    { ssu00001,
      do_show_debugfs_params,
      "Show debugfs parameters",
      0 },
    { ssu00002,
      do_open_filesys,
      "Open a filesystem",
      0 },
    { ssu00003,
      do_close_filesys,
      "Close the filesystem",
      0 },
    { ssu00004,
      do_freefrag,
      "Report free space fragmentation",
      0 },
    { ssu00005,
      do_features,
      "Set/print superblock features",
      0 },
    { ssu00006,
      do_dirty_filesys,
      "Mark the filesystem as dirty",
      0 },
    { ssu00007,
      do_init_filesys,
      "Initialize a filesystem (DESTROYS DATA)",
      0 },
    { ssu00008,
      do_show_super_stats,
      "Show superblock statistics",
      0 },
    { ssu00009,
      do_ncheck,
      "Do inode->name translation",
      0 },
    { ssu00010,
      do_icheck,
      "Do block->inode translation",
      0 },
    { ssu00011,
      do_chroot,
      "Change root directory",
      0 },
    { ssu00012,
      do_change_working_dir,
      "Change working directory",
      0 },
    { ssu00013,
      do_list_dir,
      "List directory",
      0 },
    { ssu00014,
      do_stat,
      "Show inode information ",
      0 },
    { ssu00015,
      do_dump_extents,
      "Dump extents information ",
      0 },
    { ssu00016,
      do_blocks,
      "Dump blocks used by an inode ",
      0 },
    { ssu00017,
      do_filefrag,
      "Report fragmentation information for an inode",
      0 },
    { ssu00018,
      do_link,
      "Create directory link",
      0 },
    { ssu00019,
      do_unlink,
      "Delete a directory link",
      0 },
    { ssu00020,
      do_mkdir,
      "Create a directory",
      0 },
    { ssu00021,
      do_rmdir,
      "Remove a directory",
      0 },
    { ssu00022,
      do_rm,
      "Remove a file (unlink and kill_file, if appropriate)",
      0 },
    { ssu00023,
      do_kill_file,
      "Deallocate an inode and its blocks",
      0 },
    { ssu00024,
      do_copy_inode,
      "Copy the inode structure",
      0 },
    { ssu00025,
      do_clri,
      "Clear an inode's contents",
      0 },
    { ssu00026,
      do_freei,
      "Clear an inode's in-use flag",
      0 },
    { ssu00027,
      do_seti,
      "Set an inode's in-use flag",
      0 },
    { ssu00028,
      do_testi,
      "Test an inode's in-use flag",
      0 },
    { ssu00029,
      do_freeb,
      "Clear a block's in-use flag",
      0 },
    { ssu00030,
      do_setb,
      "Set a block's in-use flag",
      0 },
    { ssu00031,
      do_testb,
      "Test a block's in-use flag",
      0 },
    { ssu00032,
      do_modify_inode,
      "Modify an inode by structure",
      0 },
    { ssu00033,
      do_find_free_block,
      "Find free block(s)",
      0 },
    { ssu00034,
      do_find_free_inode,
      "Find free inode(s)",
      0 },
    { ssu00035,
      do_print_working_directory,
      "Print current working directory",
      0 },
    { ssu00036,
      do_expand_dir,
      "Expand directory",
      0 },
    { ssu00037,
      do_mknod,
      "Create a special file",
      0 },
    { ssu00038,
      do_lsdel,
      "List deleted inodes",
      0 },
    { ssu00039,
      do_undel,
      "Undelete file",
      0 },
    { ssu00040,
      do_write,
      "Copy a file from your native filesystem",
      0 },
    { ssu00041,
      do_dump,
      "Dump an inode out to a file",
      0 },
    { ssu00042,
      do_cat,
      "Dump an inode out to stdout",
      0 },
    { ssu00043,
      do_lcd,
      "Change the current directory on your native filesystem",
      0 },
    { ssu00044,
      do_rdump,
      "Recursively dump a directory to the native filesystem",
      0 },
    { ssu00045,
      do_set_super,
      "Set superblock value",
      0 },
    { ssu00046,
      do_set_inode,
      "Set inode field",
      0 },
    { ssu00047,
      do_set_block_group_descriptor,
      "Set block group descriptor field",
      0 },
    { ssu00048,
      do_logdump,
      "Dump the contents of the journal",
      0 },
    { ssu00049,
      do_htree_dump,
      "Dump a hash-indexed directory",
      0 },
    { ssu00050,
      do_dx_hash,
      "Calculate the directory hash of a filename",
      0 },
    { ssu00051,
      do_dirsearch,
      "Search a directory for a particular filename",
      0 },
    { ssu00052,
      do_bmap,
      "Calculate the logical->physical block mapping for an inode",
      0 },
    { ssu00053,
      do_fallocate,
      "Allocate uninitialized blocks to an inode",
      0 },
    { ssu00054,
      do_punch,
      "Punch (or truncate) blocks from an inode by deallocating them",
      0 },
    { ssu00055,
      do_symlink,
      "Create a symbolic link",
      0 },
    { ssu00056,
      do_imap,
      "Calculate the location of an inode",
      0 },
    { ssu00057,
      do_dump_unused,
      "Dump unused blocks",
      0 },
    { ssu00058,
      do_set_current_time,
      "Set current time to use when setting filesystem fields",
      0 },
    { ssu00059,
      do_supported_features,
      "Print features supported by this version of e2fsprogs",
      0 },
    { ssu00060,
      do_dump_mmp,
      "Dump MMP information",
      0 },
    { ssu00061,
      do_set_mmp_value,
      "Set MMP value",
      0 },
    { ssu00062,
      do_extent_open,
      "Open inode for extent manipulation",
      0 },
    { ssu00063,
      do_zap_block,
      "Zap block: fill with 0, pattern, flip bits etc.",
      0 },
    { ssu00064,
      do_block_dump,
      "Dump contents of a block",
      0 },
    { ssu00065,
      do_list_xattr,
      "List extended attributes of an inode",
      0 },
    { ssu00066,
      do_get_xattr,
      "Get an extended attribute of an inode",
      0 },
    { ssu00067,
      do_set_xattr,
      "Set an extended attribute of an inode",
      0 },
    { ssu00068,
      do_rm_xattr,
      "Remove an extended attribute of an inode",
      0 },
    { ssu00069,
      do_list_quota,
      "List quota",
      0 },
    { ssu00070,
      do_get_quota,
      "Get quota",
      0 },
    { ssu00071,
      do_idump,
      "Dump the inode structure in hex",
      0 },
    { ssu00072,
      do_journal_open,
      "Open the journal",
      0 },
    { ssu00073,
      do_journal_close,
      "Close the journal",
      0 },
    { ssu00074,
      do_journal_write,
      "Write a transaction to the journal",
      0 },
    { ssu00075,
      do_journal_run,
      "Recover the journal",
      0 },
    { 0, 0, 0, 0 }
};

ss_request_table debug_cmds = { 2, ssu00076 };
