/* Programmable Interval Timer (channel 0) driver. */
#pragma once
#include <stdint.h>

/* Configure the PIT to fire at `frequency` Hz on IRQ0. */
void pit_install(uint32_t frequency);

/* Number of timer ticks since boot. */
uint32_t pit_ticks(void);
