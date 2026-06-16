/* VGA text-mode terminal driver (80x25, memory at 0xB8000). */
#include "kio.h"
#include "io.h"

#define VGA_WIDTH  80
#define VGA_HEIGHT 25

static volatile uint16_t *const vga_buffer = (uint16_t *)0xB8000;
static size_t  cursor_row;
static size_t  cursor_col;
static uint8_t cursor_color;

static inline uint16_t vga_entry(char c, uint8_t color)
{
    return (uint16_t)(uint8_t)c | ((uint16_t)color << 8);
}

/* Move the hardware cursor to the current position. */
static void update_cursor(void)
{
    uint16_t pos = (uint16_t)(cursor_row * VGA_WIDTH + cursor_col);
    outb(0x3D4, 0x0F);
    outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

void terminal_setcolor(enum vga_color fg, enum vga_color bg)
{
    cursor_color = (uint8_t)fg | (uint8_t)(bg << 4);
}

void terminal_clear(void)
{
    for (size_t y = 0; y < VGA_HEIGHT; y++)
        for (size_t x = 0; x < VGA_WIDTH; x++)
            vga_buffer[y * VGA_WIDTH + x] = vga_entry(' ', cursor_color);
    cursor_row = cursor_col = 0;
    update_cursor();
}

void terminal_initialize(void)
{
    cursor_color = (uint8_t)VGA_LIGHT_GREY | ((uint8_t)VGA_BLACK << 4);
    terminal_clear();
}

static void scroll(void)
{
    for (size_t y = 1; y < VGA_HEIGHT; y++)
        for (size_t x = 0; x < VGA_WIDTH; x++)
            vga_buffer[(y - 1) * VGA_WIDTH + x] = vga_buffer[y * VGA_WIDTH + x];

    for (size_t x = 0; x < VGA_WIDTH; x++)
        vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = vga_entry(' ', cursor_color);

    cursor_row = VGA_HEIGHT - 1;
}

void terminal_putchar(char c)
{
    switch (c) {
    case '\n':
        cursor_col = 0;
        cursor_row++;
        break;
    case '\r':
        cursor_col = 0;
        break;
    case '\t':
        cursor_col = (cursor_col + 4) & ~(size_t)3;
        break;
    case '\b':
        if (cursor_col > 0) {
            cursor_col--;
            vga_buffer[cursor_row * VGA_WIDTH + cursor_col] =
                vga_entry(' ', cursor_color);
        }
        break;
    default:
        vga_buffer[cursor_row * VGA_WIDTH + cursor_col] =
            vga_entry(c, cursor_color);
        cursor_col++;
        break;
    }

    if (cursor_col >= VGA_WIDTH) {
        cursor_col = 0;
        cursor_row++;
    }
    if (cursor_row >= VGA_HEIGHT)
        scroll();

    update_cursor();
}

void terminal_writestring(const char *s)
{
    while (*s)
        terminal_putchar(*s++);
}
