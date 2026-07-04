#include "serial.h"
#include "io.h"
#include "isr.h"
#include "console.h"

#define COM1 0x3F8
#define SBUF_SIZE 256

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

/* ---- RX: command channel ----
 * A ring buffer filled by the IRQ4 handler; console_read() (drivers/console.c)
 * polls it non-blockingly alongside the keyboard so either source can supply
 * shell input. */
static char sbuf[SBUF_SIZE];
static volatile int shead, stail;

static void sbuf_push(char c)
{
    int next = (stail + 1) % SBUF_SIZE;
    if (next != shead) {
        sbuf[stail] = c;
        stail = next;
    }
    console_notify();
}

static void on_serial(registers_t *regs)
{
    (void)regs;
    while (inb(COM1 + 5) & 0x01)      /* Data Ready */
        sbuf_push((char)inb(COM1));
}

/* Non-blocking peek. Caller must already hold interrupts off (see
 * drivers/console.c's console_getchar()). */
int serial_trygetchar(void)
{
    if (shead == stail)
        return -1;
    char c = sbuf[shead];
    shead = (shead + 1) % SBUF_SIZE;
    return (unsigned char)c;
}

void serial_install(void)
{
    register_interrupt_handler(36, on_serial);   /* IRQ4 -> vector 36 */
    outb(COM1 + 1, 0x01);                        /* enable "data available" IRQ */
}
