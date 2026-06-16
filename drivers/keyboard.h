/* PS/2 keyboard driver. */
#pragma once

void keyboard_install(void);

/* Blocking read of a single character from the keyboard input buffer. */
int keyboard_getchar(void);
