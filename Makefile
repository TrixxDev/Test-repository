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

# User programs are built separately. The shell is embedded into the kernel
# image as a fallback; all programs are written to the FAT32 disk.
EMBEDDED   := kernel/embedded_user.c
USER_PROGS := user/init.elf user/logger.elf user/sh.elf user/hello.elf \
              user/cat.elf user/grep.elf user/orphan.elf \
              user/netd.elf user/echosrv.elf user/echocli.elf user/save.elf
LIBC_OBJ   := user/libc/string.o user/libc/printf.o user/libc/malloc.o user/libc/net.o

C_SRC := $(shell find kernel arch drivers lib fs -name '*.c')
C_SRC := $(sort $(C_SRC) $(EMBEDDED))
S_SRC := $(shell find kernel arch drivers lib fs -name '*.S')
OBJ   := $(C_SRC:.c=.o) $(S_SRC:.S=.o)

.PHONY: all run debug clean

all: $(KERNEL) $(DISK)

$(KERNEL): $(OBJ) linker.ld
	$(LD) $(LDFLAGS) $(OBJ) -o $@
	@echo "Built $(KERNEL)"

# --- user programs (crt0 provides _start and calls main) ---
UCFLAGS := --target=$(TARGET) -m32 -ffreestanding -nostdlib -fno-pic -fno-pie \
           -O2 -Iinclude -Iuser

user/crt0.o: user/crt0.S
	$(CC) --target=$(TARGET) -m32 -ffreestanding -Iinclude -c user/crt0.S -o $@

user/libc/%.o: user/libc/%.c user/libc.h
	$(CC) $(UCFLAGS) -c $< -o $@

user/%.elf: user/%.c user/libc.h user/crt0.o $(LIBC_OBJ) user/user.ld
	$(CC) $(UCFLAGS) -c user/$*.c -o user/$*.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/$*.o $(LIBC_OBJ) -o $@

$(EMBEDDED): user/init.elf tools/bin2c.py
	python3 tools/bin2c.py user/init.elf user_elf > $(EMBEDDED)

# --- FAT32 disk image containing the user programs + a sample text file ---
$(DISK): $(USER_PROGS) user/poem.txt tools/mkfat32.py
	python3 tools/mkfat32.py $(DISK) INIT.ELF user/init.elf LOGGER.ELF user/logger.elf \
	    SH.ELF user/sh.elf HELLO.ELF user/hello.elf \
	    CAT.ELF user/cat.elf GREP.ELF user/grep.elf ORPHAN.ELF user/orphan.elf \
	    NETD.ELF user/netd.elf ECHOSRV.ELF user/echosrv.elf ECHOCLI.ELF user/echocli.elf \
	    SAVE.ELF user/save.elf POEM.TXT user/poem.txt

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
	rm -f $(OBJ) $(KERNEL) $(DISK) $(EMBEDDED) user/*.o user/*.elf user/libc/*.o
