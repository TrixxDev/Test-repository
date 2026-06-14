/* tmpfs: a simple in-memory read/write filesystem. */
#pragma once
#include "vfs.h"

/* Create a tmpfs instance and return its root directory node. */
vfs_node_t *tmpfs_create(void);
