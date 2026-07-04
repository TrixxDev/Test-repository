/* PS/2 keyboard driver. */
#pragma once

void keyboard_install(void);

/* Non-blocking: returns the next buffered key, or -1 if none is buffered.
 * Caller must hold interrupts off (see drivers/console.c's console_getchar()). */
int keyboard_trygetchar(void);
