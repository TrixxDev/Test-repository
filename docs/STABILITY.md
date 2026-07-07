# AuroraOS — Stabilization & Stress Audit (pre-1.0)

Before the 10.0 Desktop Environment work, AuroraOS went through a stabilization
pass: a sweep for the memory/process/IPC leaks and missing limits that accumulate
once a GUI is actually used. This file records what was checked, what was fixed,
and how each item was verified. The harness is `make stress` (the window-server
self-test, `user/wmstress.c`) plus the existing `make demo-*` / `tools/verify_drag.py`.

## Fixes

- **Window content-buffer leak (the big one).** The window server `malloc`s each
  window's pixel buffer in `WM_CREATE` but `wm_destroy` only freed the table slot,
  not the buffer — every open/close cycle leaked ~tens of KiB. Added
  `wm_content_ptr` + a `destroy_window()` helper that frees the buffer; used on the
  app's `WM_DESTROY`, the close button, and dead-owner reaping.
- **Buffer leak on a full table.** If `malloc` succeeded but `wm_create` failed
  (table full), the buffer was leaked. Now freed on that path.
- **Dead-owner window reaping.** If an app dies *without* closing its window
  (crash, `kill`, or the Dock which has no close button), its window used to linger
  forever. The server now distinguishes "mailbox full" from "process gone" (via
  `uid_of`) when an event delivery fails, and reaps a dead owner's windows on the
  next key/pointer event — so a crashed Dock/Finder/Terminal leaves no ghost.
- **Destroy ownership check.** `WM_DESTROY` now only destroys a window owned by the
  requester, so a buggy/hostile app can't destroy another app's window.

## Audit checklist

| # | Check | Result | How |
|---|-------|--------|-----|
| 1 | Window memory leak (open/close ×N) | ✅ no leak | `make stress`: heap top (`brk`) is **identical** after round 1 and round 2 of 50 create/destroy cycles (steady state). Round 1's one-time growth is the allocator reaching its working set. |
| 2 | Zombie processes | ✅ reaped | Closing a Dock-launched Finder logs `[init] reaped adopted child pid N (exit 0)`; apps double-fork so they reparent to init, which reaps them. |
| 3 | Window-table limit | ✅ graceful | `make stress` phase 2 fills the table: 13 of 24 creates succeed (3 already live + 13 = `WM_MAX_WINDOWS` 16), the rest return `status < 0` with no crash. |
| 4 | IPC mailbox overflow | ✅ bounded | `sys_msgsend` drops (returns −1) at `MBOX_LIMIT`; senders treat −1 as "dropped" and continue — never a hang. `deliver()` only reaps on confirmed death, not on a full mailbox. |
| 5 | Closing the Dock | ✅ safe | The Dock is borderless (no close button) by design; if killed externally, its window is reaped on the next pointer event and the OS keeps running. |
| 6 | Closing the Finder + relaunch | ✅ works | Live: open from Dock → close (red button) → `[files] closed` + init reaps → click the Dock's Files icon → a fresh Finder (new pid/window), no ghost. |
| 7 | Stress drag / z-order | ✅ stable | The compositor is damage-driven and pixel-identical to a full repaint (see GRAPHICS.md); `tools/verify_drag.py` pixel-asserts drag + close; the stress test creates 13 simultaneous windows with no artifacts. |
| 8 | Large file in the Viewer | ✅ bounded | The Viewer caps a file at `VIEWER_MAX_FILE` (64 KiB) and `MAX_LINES` (4096) and clamps scrolling, so a big file is read/scrolled without overrun or crash (a 50 KiB text file fits well within both caps). |

## Known limitations (acceptable for 1.0)

- `free()` never returns memory to the kernel (the user `sbrk` heap doesn't shrink),
  so `brk` records a high-water mark; freed blocks are reused, which is what the
  steady-state stress result confirms.
- Dead-owner reaping is lazy (on the next input event over the window) and uses
  `uid_of` to confirm death; a very fast pid reuse could briefly mis-ident a slot.
  Not observed in practice; a future SIGCHLD-style notification would make it eager.
- No per-app window cap yet (only the global `WM_MAX_WINDOWS`).

## Reproduce

```sh
make stress        # window-server leak / limit self-test (Dock "E" icon)
make demo-files    # Dock -> Finder -> launch a Terminal
make demo-view     # Dock -> Finder -> Viewer (render + scroll)
python3 tools/verify_drag.py   # pixel-asserted drag + close
```
