# AuroraOS build system.
#
# Uses clang as a cross-compiler (no separate cross-toolchain needed) targeting
# bare-metal i686, and LLVM's lld as the linker. The result is a Multiboot1
# kernel that can be booted directly with `qemu-system-i386 -kernel`.

CC      := clang
LD      := ld.lld
TARGET  := i686-elf

INCLUDES := -Iinclude -Iarch/i386 -Idrivers -Ilib -Ikernel -Ifs

CFLAGS  := --target=$(TARGET) -m32 -ffreestanding -nostdlib \
           -fno-pic -fno-pie -fno-stack-protector \
           -std=gnu11 -O2 -g -Wall -Wextra $(INCLUDES)

ASFLAGS := --target=$(TARGET) -m32 -ffreestanding $(INCLUDES)

LDFLAGS := -m elf_i386 -no-pie -T linker.ld

KERNEL  := aurora.elf
DISK    := disk.img

# The user program is built separately and embedded into the kernel image so it
# can be loaded by the ELF loader at runtime (also written to the FAT32 disk).
USER_ELF   := user/hello.elf
EMBEDDED   := kernel/embedded_user.c

C_SRC := $(shell find kernel arch drivers lib fs -name '*.c')
C_SRC := $(sort $(C_SRC) $(EMBEDDED))
S_SRC := $(shell find kernel arch drivers lib fs -name '*.S')
OBJ   := $(C_SRC:.c=.o) $(S_SRC:.S=.o)

.PHONY: all run debug clean

all: $(KERNEL) $(DISK)

$(KERNEL): $(OBJ) linker.ld
	$(LD) $(LDFLAGS) $(OBJ) -o $@
	@echo "Built $(KERNEL)"

# --- user program -> embedded blob ---
$(USER_ELF): user/hello.c user/user.ld
	$(CC) --target=$(TARGET) -m32 -ffreestanding -nostdlib -fno-pic -fno-pie \
	      -O2 -c user/hello.c -o user/hello.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/hello.o -o $@

$(EMBEDDED): $(USER_ELF) tools/bin2c.py
	python3 tools/bin2c.py $(USER_ELF) user_elf > $(EMBEDDED)

# --- FAT32 disk image containing the user program ---
$(DISK): $(USER_ELF) tools/mkfat32.py
	python3 tools/mkfat32.py $(DISK) HELLO.ELF $(USER_ELF)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(ASFLAGS) -c $< -o $@

# Boot the kernel in QEMU with the FAT32 disk attached as the primary IDE drive.
run: $(KERNEL) $(DISK)
	qemu-system-i386 -kernel $(KERNEL) -serial stdio -m 64M \
	    -drive file=$(DISK),format=raw,if=ide

# Same, but wait for a GDB connection on :1234.
debug: $(KERNEL) $(DISK)
	qemu-system-i386 -kernel $(KERNEL) -serial stdio -m 64M \
	    -drive file=$(DISK),format=raw,if=ide -s -S

clean:
	rm -f $(OBJ) $(KERNEL) $(DISK) $(EMBEDDED) user/hello.o $(USER_ELF)
