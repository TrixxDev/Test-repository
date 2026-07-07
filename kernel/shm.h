/* Shared-memory surfaces (zero-copy window content).
 *
 * A small pool of physical-frame-backed objects that can be mapped into more than
 * one address space at the same virtual address, so a GUI client can render
 * directly into a buffer the window server composites from — no per-draw IPC.
 *
 * Lifecycle (reference-counted): the window server (the owner) creates an object
 * (shm_create), maps it (shm_map), grants a client map access (shm_grant), and
 * hands the id to that client, which maps the same id at the same address and
 * draws into it. Each mapper holds a reference; the frames are freed only once the
 * object is destroyed (shm_destroy by the creator, or the creator exiting) *and*
 * the reference count reaches zero. A mapper's address-space teardown drops its
 * reference (shm_release_proc) without freeing the frames while others map them,
 * so there is no double free and no use-after-free across a realloc-on-resize.
 *
 * Access control (grant model): shm_map succeeds only for the creator, the single
 * granted client, or a public object (SHM_PUBLIC). Only the creator may grant or
 * destroy. See syscall_abi.h for SHM_PUBLIC. */
#pragma once
#include <stdint.h>

struct process;

/* Allocate a shared object of `size` bytes (rounded up to whole frames). `flags`
 * may be SHM_PUBLIC (any process may map it). Returns its id (>= 0) or -1. The
 * caller (creator) owns its lifetime. */
int      shm_create(uint32_t size, uint32_t flags);

/* Map object `id` into the current address space at its fixed slot address and
 * return that address (0 on error or if the caller lacks access). Idempotent per
 * process. The server and its granted client both call this. */
uint32_t shm_map(int id);

/* Unmap object `id` from the current address space (drops this process's
 * reference). Returns 0, or -1 if the caller had not mapped it. */
int      shm_unmap(int id);

/* Grant process `pid` permission to shm_map object `id`. Creator only; -1 on
 * error. (The clipboard uses SHM_PUBLIC instead of a per-client grant.) */
int      shm_grant(int id, int pid);

/* Destroy object `id`: unmap it from the caller, mark it destroyed, and free its
 * frames once no address space still maps it. Creator only; -1 on error. */
int      shm_destroy(int id);

/* Drop all references held by an exiting/exec'ing process and destroy the objects
 * it created (frees deferred to the last mapper). Called from process teardown. */
void     shm_release_proc(struct process *p);
