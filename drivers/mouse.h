/* PS/2 mouse driver — raw pointer events for the userspace window server.
 *
 * The kernel does the minimum: enable the 8042 aux device, handle IRQ12,
 * assemble the 3-byte packet, and buffer (dx, dy, buttons) for a blocking
 * reader. Cursor, hit-testing, focus and dragging are all userspace policy in
 * the window server (see docs/INPUT.md). */
#pragma once

void mouse_install(void);

/* Blocking read of one pointer event. dx/dy are in screen orientation
 * (dy > 0 means downward); buttons: bit0 = left, bit1 = right, bit2 = middle. */
void mouse_get(int *dx, int *dy, int *buttons);
