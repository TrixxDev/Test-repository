# AuroraOS build system.
#
# Uses clang as a cross-compiler (no separate cross-toolchain needed) targeting
# bare-metal i686, and LLVM's lld as the linker. The result is a Multiboot1
# kernel that can be booted directly with `qemu-system-i386 -kernel`.

CC      := clang
LD      := ld.lld
TARGET  := i686-elf

INCLUDES := -Iinclude -Iarch/i386 -Idrivers -Ilib -Ikernel

CFLAGS  := --target=$(TARGET) -m32 -ffreestanding -nostdlib \
           -fno-pic -fno-pie -fno-stack-protector \
           -std=gnu11 -O2 -g -Wall -Wextra $(INCLUDES)

ASFLAGS := --target=$(TARGET) -m32 -ffreestanding $(INCLUDES)

LDFLAGS := -m elf_i386 -no-pie -T linker.ld

KERNEL  := aurora.elf

C_SRC := $(shell find kernel arch drivers lib -name '*.c')
S_SRC := $(shell find kernel arch drivers lib -name '*.S')
OBJ   := $(C_SRC:.c=.o) $(S_SRC:.S=.o)

.PHONY: all run debug clean

all: $(KERNEL)

$(KERNEL): $(OBJ) linker.ld
	$(LD) $(LDFLAGS) $(OBJ) -o $@
	@echo "Built $(KERNEL)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(ASFLAGS) -c $< -o $@

# Boot the kernel in QEMU. Serial output (kernel log) is mirrored to stdio.
run: $(KERNEL)
	qemu-system-i386 -kernel $(KERNEL) -serial stdio -m 64M

# Same, but wait for a GDB connection on :1234.
debug: $(KERNEL)
	qemu-system-i386 -kernel $(KERNEL) -serial stdio -m 64M -s -S

clean:
	rm -f $(OBJ) $(KERNEL)
