/* PS/2 keyboard driver. */
#pragma once

void keyboard_install(void);

/* Non-blocking: returns the next buffered key, or -1 if none is buffered.
 * Caller must hold interrupts off (see drivers/console.c's console_getchar()). */
int keyboard_trygetchar(void);

/* Non-blocking, non-destructive: 1 if a key is buffered, 0 otherwise. Same
 * interrupts-off contract. */
int keyboard_has_data(void);
