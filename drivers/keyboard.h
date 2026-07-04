/* PS/2 keyboard driver. */
#pragma once

void keyboard_install(void);

/* Blocking read of a single character from the keyboard input buffer. */
int keyboard_getchar(void);

/* Non-blocking: returns the next buffered key, or -1 if none is buffered. */
int keyboard_trygetchar(void);
