#include "pit.h"
#include "isr.h"
#include "io.h"

#define PIT_FREQUENCY 1193180

static volatile uint32_t ticks;
static void (*tick_hook)(void);

static void on_tick(registers_t *regs)
{
    (void)regs;
    ticks++;
    if (tick_hook)
        tick_hook();
}

void pit_set_tick_hook(void (*hook)(void))
{
    tick_hook = hook;
}

void pit_install(uint32_t frequency)
{
    uint32_t divisor = PIT_FREQUENCY / frequency;

    outb(0x43, 0x36);                               /* channel 0, lobyte/hibyte, mode 3 */
    outb(0x40, (uint8_t)(divisor & 0xFF));
    outb(0x40, (uint8_t)((divisor >> 8) & 0xFF));

    register_interrupt_handler(32, on_tick);        /* IRQ0 -> vector 32 */
}

uint32_t pit_ticks(void)
{
    return ticks;
}
