#include "serial.h"
#include "io.h"

#define COM1 0x3F8

void serial_init(void)
{
    outb(COM1 + 1, 0x00);   /* disable interrupts */
    outb(COM1 + 3, 0x80);   /* enable DLAB (set baud divisor) */
    outb(COM1 + 0, 0x03);   /* divisor low: 38400 baud */
    outb(COM1 + 1, 0x00);   /* divisor high */
    outb(COM1 + 3, 0x03);   /* 8 bits, no parity, one stop bit */
    outb(COM1 + 2, 0xC7);   /* enable FIFO, clear, 14-byte threshold */
    outb(COM1 + 4, 0x0B);   /* IRQs enabled, RTS/DSR set */
}

static int transmit_empty(void)
{
    return inb(COM1 + 5) & 0x20;
}

void serial_write_char(char c)
{
    if (c == '\n')
        serial_write_char('\r');
    while (!transmit_empty())
        ;
    outb(COM1, (uint8_t)c);
}
