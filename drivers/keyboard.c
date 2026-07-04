/* PS/2 keyboard driver: scancode set 1 -> ASCII, echo, and an input buffer
 * console_read() (drivers/console.c) polls alongside the serial command
 * channel. */
#include "keyboard.h"
#include "isr.h"
#include "io.h"
#include "kio.h"
#include "keys.h"
#include "console.h"

#define KBD_DATA_PORT 0x60
#define KBD_STATUS    0x64
#define KBUF_SIZE 256

static const char keymap[128] = {
    0,   27, '1','2','3','4','5','6','7','8','9','0','-','=','\b',
    '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',
    0,   'a','s','d','f','g','h','j','k','l',';','\'','`',
    0,   '\\','z','x','c','v','b','n','m',',','.','/', 0,
    '*', 0,  ' ',
};

static const char keymap_shift[128] = {
    0,   27, '!','@','#','$','%','^','&','*','(',')','_','+','\b',
    '\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n',
    0,   'A','S','D','F','G','H','J','K','L',':','"','~',
    0,   '|','Z','X','C','V','B','N','M','<','>','?', 0,
    '*', 0,  ' ',
};

static int shift_down;
static int ctrl_down;        /* left/right Control held (for Ctrl+key combos) */
static int extended;        /* set by the 0xE0 prefix; next byte is an ext. key */

/* Map an extended (0xE0-prefixed) make code to a KEY_* code, or 0 if unhandled. */
static char extended_key(uint8_t sc)
{
    switch (sc) {
    case 0x48: return KEY_UP;
    case 0x50: return KEY_DOWN;
    case 0x4B: return KEY_LEFT;
    case 0x4D: return KEY_RIGHT;
    case 0x49: return KEY_PGUP;
    case 0x51: return KEY_PGDN;
    case 0x47: return KEY_HOME;
    case 0x4F: return KEY_END;
    default:   return 0;
    }
}

static char     kbuf[KBUF_SIZE];
static volatile int khead, ktail;

static void kbuf_push(char c)
{
    int next = (ktail + 1) % KBUF_SIZE;
    if (next != khead) {
        kbuf[ktail] = c;
        ktail = next;
    }
    console_notify();
}

static void on_key(registers_t *regs)
{
    (void)regs;
    /* Ignore aux-port (mouse) bytes if IRQ1 fires for them — reading here would
     * desync the PS/2 mouse packet stream. */
    if (inb(KBD_STATUS) & 0x20)
        return;
    uint8_t scancode = inb(KBD_DATA_PORT);

    if (scancode == 0xE0) {     /* prefix: the next byte is an extended key */
        extended = 1;
        return;
    }

    if (scancode & 0x80) {      /* a key was released */
        uint8_t released = scancode & 0x7F;
        if (!extended && (released == 0x2A || released == 0x36))
            shift_down = 0;
        if (released == 0x1D)   /* left or right Control (0xE0-prefixed) released */
            ctrl_down = 0;
        extended = 0;           /* consume the extended release too */
        return;
    }

    if (extended) {             /* an extended make: arrows, PgUp/PgDn, Home/End */
        extended = 0;
        if (scancode == 0x1D) { ctrl_down = 1; return; }   /* right Control */
        char k = extended_key(scancode);
        if (k)
            kbuf_push(k);       /* no echo for control keys */
        return;
    }

    if (scancode == 0x2A || scancode == 0x36) {
        shift_down = 1;
        return;
    }
    if (scancode == 0x1D) {     /* left Control */
        ctrl_down = 1;
        return;
    }

    char c = shift_down ? keymap_shift[scancode] : keymap[scancode];
    if (c) {
        if (ctrl_down && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) {
            c = (char)((c | 0x20) - 'a' + 1);   /* Ctrl+letter -> 1..26, no echo */
            kbuf_push(c);
        } else {
            kputchar(c);        /* local echo */
            kbuf_push(c);
        }
    }
}

void keyboard_install(void)
{
    register_interrupt_handler(33, on_key);     /* IRQ1 -> vector 33 */
}

/* Non-blocking peek, used by console_read() to poll the keyboard alongside
 * the serial command channel. Caller must already hold interrupts off (this
 * runs inside console_read()'s own cli/sti window so the two sources can be
 * checked, and a wakeup registered, as one atomic step). */
int keyboard_trygetchar(void)
{
    if (khead == ktail)
        return -1;
    char c = kbuf[khead];
    khead = (khead + 1) % KBUF_SIZE;
    return (unsigned char)c;
}
