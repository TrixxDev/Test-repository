/* PS/2 mouse driver — see mouse.h. Mirrors the keyboard driver: an IRQ handler
 * fills a ring buffer that a blocking reader (the window server's mouse helper)
 * drains. No cursor/focus policy here; the kernel only delivers raw packets. */
#include "mouse.h"
#include "isr.h"
#include "io.h"
#include "scheduler.h"
#include <stddef.h>

#define PS2_DATA   0x60
#define PS2_STATUS 0x64
#define PS2_CMD    0x64

typedef struct { int dx, dy, buttons; } mevent_t;

#define MBUF_SIZE 128
static mevent_t mbuf[MBUF_SIZE];
static volatile int mhead, mtail;
static thread_t *mwaiter;

static uint8_t packet[3];   /* the 3 bytes of the current packet      */
static int     pkt_idx;     /* which byte we expect next (0, 1, 2)    */

static void mbuf_push(int dx, int dy, int buttons)
{
    int next = (mtail + 1) % MBUF_SIZE;
    if (next != mhead) {                 /* drop on overflow (motion is lossy) */
        mbuf[mtail].dx = dx;
        mbuf[mtail].dy = dy;
        mbuf[mtail].buttons = buttons;
        mtail = next;
    }
    if (mwaiter) {
        thread_wake(mwaiter);
        mwaiter = NULL;
    }
}

/* Wait until the 8042 input buffer is empty (safe to write a command/byte). */
static void ps2_wait_write(void)
{
    for (int i = 0; i < 100000; i++)
        if (!(inb(PS2_STATUS) & 0x02))
            return;
}

/* Wait until the 8042 output buffer is full (a byte is ready to read). */
static void ps2_wait_read(void)
{
    for (int i = 0; i < 100000; i++)
        if (inb(PS2_STATUS) & 0x01)
            return;
}

/* Send a command byte to the mouse (prefixed with 0xD4) and eat its ACK. */
static void mouse_command(uint8_t cmd)
{
    ps2_wait_write(); outb(PS2_CMD, 0xD4);     /* "next data byte -> mouse" */
    ps2_wait_write(); outb(PS2_DATA, cmd);
    ps2_wait_read();  (void)inb(PS2_DATA);     /* ACK (0xFA) */
}

static void on_mouse(registers_t *regs)
{
    (void)regs;
    uint8_t status = inb(PS2_STATUS);
    if (!(status & 0x20))           /* bit5: byte came from the aux (mouse) port */
        return;
    uint8_t data = inb(PS2_DATA);

    switch (pkt_idx) {
    case 0:
        if (!(data & 0x08))         /* bit3 of byte 0 is always 1; else resync */
            return;
        packet[0] = data;
        pkt_idx = 1;
        break;
    case 1:
        packet[1] = data;
        pkt_idx = 2;
        break;
    case 2: {
        packet[2] = data;
        pkt_idx = 0;
        uint8_t f = packet[0];
        if (f & 0xC0)               /* X/Y overflow: discard this packet */
            break;
        int dx = (int)packet[1] - ((f & 0x10) ? 256 : 0);   /* sign-extend X */
        int dy = (int)packet[2] - ((f & 0x20) ? 256 : 0);   /* sign-extend Y */
        int buttons = f & 0x07;
        mbuf_push(dx, dy, buttons);
        break;
    }
    }
}

void mouse_get(int *dx, int *dy, int *buttons)
{
    for (;;) {
        __asm__ volatile("cli");
        if (mhead != mtail) {
            mevent_t e = mbuf[mhead];
            mhead = (mhead + 1) % MBUF_SIZE;
            __asm__ volatile("sti");
            /* PS/2 relative -> screen coords (X right+, Y down+). */
            if (dx) *dx = -e.dx;
            if (dy) *dy = e.dy;
            if (buttons) *buttons = e.buttons;
            return;
        }
        mwaiter = thread_current();
        thread_block();             /* yields with interrupts off; wakes on input */
    }
}

void mouse_install(void)
{
    ps2_wait_write(); outb(PS2_CMD, 0xA8);          /* enable the aux device */

    /* Turn on IRQ12 and the aux clock in the controller config byte. */
    ps2_wait_write(); outb(PS2_CMD, 0x20);          /* read config byte */
    ps2_wait_read();
    uint8_t cfg = inb(PS2_DATA);
    cfg |=  0x02;                                    /* bit1: enable aux IRQ12 */
    cfg &= ~0x20;                                    /* bit5: enable aux clock */
    ps2_wait_write(); outb(PS2_CMD, 0x60);          /* write config byte */
    ps2_wait_write(); outb(PS2_DATA, cfg);

    mouse_command(0xF6);            /* set defaults (scale, sample rate, etc.) */
    mouse_command(0xF4);            /* enable data reporting */

    register_interrupt_handler(44, on_mouse);       /* IRQ12 -> vector 44 */
}
