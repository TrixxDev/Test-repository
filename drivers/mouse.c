/* PS/2 mouse driver — see mouse.h. Mirrors the keyboard driver: an IRQ handler
 * fills a ring buffer that a blocking reader (the window server's mouse helper)
 * drains. No cursor/focus policy here; the kernel only delivers raw packets. */
#include "mouse.h"
#include "isr.h"
#include "io.h"
#include "kio.h"
#include "scheduler.h"
#include <stddef.h>

#define PS2_DATA   0x60
#define PS2_STATUS 0x64
#define PS2_CMD    0x64

/* ---- QEMU/VMware "vmmouse" absolute-pointer backdoor ----------------------
 * A single I/O port (0x5658) read, with the command in registers, exchanges
 * data with the hypervisor. The device piggybacks on the PS/2 IRQ12, so the
 * IRQ handler below still assembles a (now ignored) PS/2 packet and then reads
 * the absolute position out of the backdoor. See drivers/mouse.h. */
#define VMM_MAGIC   0x564D5868u          /* 'VMXh' */
#define VMM_PORT    0x5658
#define VMM_GETVERSION         10
#define VMM_ABSPOINTER_DATA    39
#define VMM_ABSPOINTER_STATUS  40
#define VMM_ABSPOINTER_COMMAND 41
#define VMM_CMD_READID         0x45414552u   /* enable / identify */
#define VMM_CMD_ABSOLUTE       0x53424152u   /* request absolute mode */
#define VMM_STATUS_ERROR       0xFFFF0000u

static int vmmouse_on;       /* 1 once absolute mode is live */

static inline void vmm_call(uint32_t cmd, uint32_t arg,
                            uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    uint32_t ra, rb, rc, rd;
    __asm__ volatile("inl %%dx, %%eax"
        : "=a"(ra), "=b"(rb), "=c"(rc), "=d"(rd)
        : "a"(VMM_MAGIC), "b"(arg), "c"(cmd), "d"(VMM_PORT));
    if (a) *a = ra; if (b) *b = rb; if (c) *c = rc; if (d) *d = rd;
}

/* Probe + switch the vmmouse into absolute mode. Returns 1 on success. */
static int vmmouse_enable(void)
{
    uint32_t a = 0, b = 0;
    vmm_call(VMM_GETVERSION, ~0u, &a, &b, 0, 0);
    if (b != VMM_MAGIC || a == 0xFFFFFFFFu)
        return 0;                            /* no vmmouse here (e.g. real HW) */
    vmm_call(VMM_ABSPOINTER_COMMAND, VMM_CMD_READID, 0, 0, 0, 0);
    /* READID queues a version word; consume it so later 4-word event reads stay
     * aligned (otherwise every (buttons,x,y,z) packet is off by one). */
    vmm_call(VMM_ABSPOINTER_STATUS, 0, &a, 0, 0, 0);
    if ((a & 0xFFFFu) > 0)
        vmm_call(VMM_ABSPOINTER_DATA, a & 0xFFFFu, 0, 0, 0, 0);
    vmm_call(VMM_ABSPOINTER_COMMAND, VMM_CMD_ABSOLUTE, 0, 0, 0, 0);
    vmmouse_on = 1;
    return 1;
}

typedef struct { int x, y, buttons, abs; } mevent_t;

#define MBUF_SIZE 128
static mevent_t mbuf[MBUF_SIZE];
static volatile int mhead, mtail;
static thread_t *mwaiter;

static uint8_t packet[3];   /* the 3 bytes of the current packet      */
static int     pkt_idx;     /* which byte we expect next (0, 1, 2)    */

static void mbuf_push(int x, int y, int buttons, int abs)
{
    int next = (mtail + 1) % MBUF_SIZE;
    if (next != mhead) {                 /* drop on overflow (motion is lossy) */
        mbuf[mtail].x = x;
        mbuf[mtail].y = y;
        mbuf[mtail].buttons = buttons;
        mbuf[mtail].abs = abs;
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
        if (vmmouse_on) {
            /* The PS/2 packet only served to raise IRQ12; the real (absolute)
             * position lives in the backdoor queue. */
            uint32_t st = 0, bt = 0, ax = 0, ay = 0;
            vmm_call(VMM_ABSPOINTER_STATUS, 0, &st, 0, 0, 0);
            if ((st & 0xFFFF0000u) == VMM_STATUS_ERROR) {
                vmmouse_on = 0;     /* device error: drop back to PS/2 relative */
            } else if ((st & 0xFFFFu) >= 4) {        /* one event == 4 words */
                vmm_call(VMM_ABSPOINTER_DATA, 4, &bt, &ax, &ay, 0);
                int buttons = 0;                     /* vmmouse button bits */
                if (bt & 0x20) buttons |= 1;         /* left   */
                if (bt & 0x10) buttons |= 2;         /* right  */
                if (bt & 0x08) buttons |= 4;         /* middle */
                mbuf_push((int)(ax & 0xFFFFu), (int)(ay & 0xFFFFu), buttons, 1);
            }
            break;                  /* word count 0..3: spurious, nothing to do */
        }
        int dx = (int)packet[1] - ((f & 0x10) ? 256 : 0);   /* sign-extend X */
        int dy = (int)packet[2] - ((f & 0x20) ? 256 : 0);   /* sign-extend Y */
        int buttons = f & 0x07;
        mbuf_push(dx, dy, buttons, 0);
        break;
    }
    }
}

void mouse_get(int *x, int *y, int *buttons, int *absolute)
{
    for (;;) {
        __asm__ volatile("cli");
        if (mhead != mtail) {
            mevent_t e = mbuf[mhead];
            mhead = (mhead + 1) % MBUF_SIZE;
            __asm__ volatile("sti");
            if (e.abs) {
                if (x) *x = e.x;            /* absolute 0..0xFFFF (top-left origin) */
                if (y) *y = e.y;
            } else {
                /* PS/2 relative -> screen coords (X right+, Y down+). */
                if (x) *x = -e.x;
                if (y) *y =  e.y;
            }
            if (buttons)  *buttons  = e.buttons;
            if (absolute) *absolute = e.abs;
            return;
        }
        mwaiter = thread_current();
        thread_block();             /* yields with interrupts off; wakes on input */
    }
}

void mouse_install(int absolute)
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

    /* Opt-in absolute pointer (QEMU/VMware) so the cursor tracks the host. */
    if (absolute && vmmouse_enable())
        kprintf("[mouse] vmmouse absolute mode enabled\n");
}
