/* PS/2 mouse driver — raw pointer events for the userspace window server.
 *
 * The kernel does the minimum: enable the 8042 aux device, handle IRQ12,
 * assemble the 3-byte packet, and buffer (dx, dy, buttons) for a blocking
 * reader. Cursor, hit-testing, focus and dragging are all userspace policy in
 * the window server (see docs/INPUT.md).
 *
 * Optionally (when `absolute` is set, i.e. the kernel booted with `abs` on the
 * cmdline) it also drives the QEMU/VMware "vmmouse" backdoor: each event then
 * carries an ABSOLUTE position in the 0..0xFFFF range, which the window server
 * scales to the current resolution so the guest cursor tracks the host pointer
 * exactly at any video mode. PS/2 relative motion is the fallback. */
#pragma once

void mouse_install(int absolute);

/* Blocking read of one pointer event.
 *   *absolute == 0 : x/y are relative deltas in screen orientation (y>0 = down).
 *   *absolute == 1 : x/y are an absolute position in 0..0xFFFF (vmmouse).
 * buttons: bit0 = left, bit1 = right, bit2 = middle. Any out pointer may be NULL. */
void mouse_get(int *x, int *y, int *buttons, int *absolute);
