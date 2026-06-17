/* Shared-memory surfaces (zero-copy window content).
 *
 * A small pool of physical-frame-backed objects that can be mapped into more than
 * one address space at the same virtual address, so a GUI client can render
 * directly into a buffer the window server composites from — no per-draw IPC.
 *
 * Lifecycle: the window server (the owner) creates an object (shm_create), maps it
 * (shm_map), and hands the id to the client, which maps the same id at the same
 * address and draws into it. The frames are freed only by an explicit shm_destroy
 * (the server, on window destroy) or when the creating process exits
 * (shm_release_pid). A mapper's address-space teardown never frees the frames
 * (their PTEs carry PAGE_SHARED), so there is no double free. */
#pragma once
#include <stdint.h>

/* Allocate a shared object of `size` bytes (rounded up to whole frames). Returns
 * its id (>= 0) or -1 on failure. The caller (creator) owns its lifetime. */
int      shm_create(uint32_t size);

/* Map object `id` into the current address space at its fixed slot address and
 * return that address (0 on error). Both the server and the client call this. */
uint32_t shm_map(int id);

/* Free object `id`: unmap it from the current space and release its frames. */
int      shm_destroy(int id);

/* Release every object created by `pid` (called from process teardown so a dead
 * creator never leaks shared frames). */
void     shm_release_pid(int pid);
