/* Console device exposed as a VFS node, used for stdin/stdout/stderr. */
#pragma once
#include "vfs.h"

vfs_node_t *console_node(void);
