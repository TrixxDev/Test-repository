/* PS/2 keyboard driver: scancode set 1 -> ASCII, echo, and an input buffer that
 * blocking readers (stdin) can wait on. */
#include "keyboard.h"
#include "isr.h"
#include "io.h"
#include "kio.h"
#include "scheduler.h"

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

static char     kbuf[KBUF_SIZE];
static volatile int khead, ktail;
static thread_t *waiter;

static void kbuf_push(char c)
{
    int next = (ktail + 1) % KBUF_SIZE;
    if (next != khead) {
        kbuf[ktail] = c;
        ktail = next;
    }
    if (waiter) {
        thread_wake(waiter);
        waiter = NULL;
    }
}

static void on_key(registers_t *regs)
{
    (void)regs;
    /* Ignore aux-port (mouse) bytes if IRQ1 fires for them — reading here would
     * desync the PS/2 mouse packet stream. */
    if (inb(KBD_STATUS) & 0x20)
        return;
    uint8_t scancode = inb(KBD_DATA_PORT);

    if (scancode & 0x80) {
        uint8_t released = scancode & 0x7F;
        if (released == 0x2A || released == 0x36)
            shift_down = 0;
        return;
    }
    if (scancode == 0x2A || scancode == 0x36) {
        shift_down = 1;
        return;
    }

    char c = shift_down ? keymap_shift[scancode] : keymap[scancode];
    if (c) {
        kputchar(c);        /* local echo */
        kbuf_push(c);
    }
}

/* Blocking read of one character from the keyboard buffer. */
int keyboard_getchar(void)
{
    for (;;) {
        __asm__ volatile("cli");
        if (khead != ktail) {
            char c = kbuf[khead];
            khead = (khead + 1) % KBUF_SIZE;
            __asm__ volatile("sti");
            return (unsigned char)c;
        }
        waiter = thread_current();
        thread_block();     /* yields with interrupts off; resumes on input */
    }
}

void keyboard_install(void)
{
    register_interrupt_handler(33, on_key);     /* IRQ1 -> vector 33 */
}
