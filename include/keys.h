/* AuroraOS special key codes — shared by the kernel keyboard driver and user
 * apps. Extended (0xE0-prefixed) PS/2 keys that have no ASCII value are mapped
 * to bytes in 0x80..0x8F, so they flow through the existing char-based input
 * pipeline (keyboard buffer -> console read -> WM_KEY) without colliding with
 * printable ASCII (0x20..0x7E). Apps that don't care simply ignore them. */
#pragma once

#define KEY_UP    0x80
#define KEY_DOWN  0x81
#define KEY_LEFT  0x82
#define KEY_RIGHT 0x83
#define KEY_PGUP  0x84
#define KEY_PGDN  0x85
#define KEY_HOME  0x86
#define KEY_END   0x87
