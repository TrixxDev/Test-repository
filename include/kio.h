/* Kernel console + formatted output. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* VGA text colors (foreground/background nibbles). */
enum vga_color {
    VGA_BLACK = 0, VGA_BLUE, VGA_GREEN, VGA_CYAN,
    VGA_RED, VGA_MAGENTA, VGA_BROWN, VGA_LIGHT_GREY,
    VGA_DARK_GREY, VGA_LIGHT_BLUE, VGA_LIGHT_GREEN, VGA_LIGHT_CYAN,
    VGA_LIGHT_RED, VGA_LIGHT_MAGENTA, VGA_LIGHT_BROWN, VGA_WHITE,
};

void terminal_initialize(void);
void terminal_clear(void);
void terminal_setcolor(enum vga_color fg, enum vga_color bg);
void terminal_putchar(char c);
void terminal_writestring(const char *s);

/* Writes to both the VGA text screen and the serial port. */
void kputchar(char c);
void kputs(const char *s);

/* Minimal printf: supports %c %s %d %i %u %x %X %p %%. */
void kprintf(const char *fmt, ...);
