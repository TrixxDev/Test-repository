/* PS/2 keyboard driver: translates scancode set 1 to ASCII and echoes input. */
#include "keyboard.h"
#include "isr.h"
#include "io.h"
#include "kio.h"

#define KBD_DATA_PORT 0x60

/* US QWERTY layout, scancode set 1, unshifted. */
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

static void on_key(registers_t *regs)
{
    (void)regs;
    uint8_t scancode = inb(KBD_DATA_PORT);

    /* High bit set => key release. */
    if (scancode & 0x80) {
        uint8_t released = scancode & 0x7F;
        if (released == 0x2A || released == 0x36)   /* left/right shift */
            shift_down = 0;
        return;
    }

    if (scancode == 0x2A || scancode == 0x36) {
        shift_down = 1;
        return;
    }

    char c = shift_down ? keymap_shift[scancode] : keymap[scancode];
    if (c)
        kputchar(c);
}

void keyboard_install(void)
{
    register_interrupt_handler(33, on_key);         /* IRQ1 -> vector 33 */
}
