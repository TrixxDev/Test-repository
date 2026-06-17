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
           -mno-sse -mno-mmx -mno-sse2 \
           -std=gnu11 -O2 -g -Wall -Wextra $(INCLUDES)

ASFLAGS := --target=$(TARGET) -m32 -ffreestanding $(INCLUDES)

LDFLAGS := -m elf_i386 -no-pie -T linker.ld

KERNEL  := aurora.elf
DISK    := disk.img

# Default GUI display backend (override: make gui GUI_DISPLAY='-display gtk,grab-on-hover=on')
GUI_DISPLAY ?= -display sdl

# User programs are built separately. The shell is embedded into the kernel
# image as a fallback; all programs are written to the FAT32 disk.
EMBEDDED   := kernel/embedded_user.c
USER_PROGS := user/init.elf user/logger.elf user/sh.elf user/hello.elf \
              user/cat.elf user/grep.elf user/orphan.elf \
              user/netd.elf user/echosrv.elf user/echocli.elf user/save.elf \
              user/wserver.elf user/term.elf user/dock.elf user/files.elf \
              user/viewer.elf user/wmstress.elf user/settings.elf
LIBC_OBJ   := user/libc/string.o user/libc/printf.o user/libc/malloc.o user/libc/net.o
# Portable graphics/compositor code, built for userspace and linked into wserver.
WM_OBJ     := user/gfx_u.o user/desktop_u.o user/wm_u.o

C_SRC := $(shell find kernel arch drivers lib fs -name '*.c')
C_SRC := $(sort $(C_SRC) $(EMBEDDED))
S_SRC := $(shell find kernel arch drivers lib fs -name '*.S')
OBJ   := $(C_SRC:.c=.o) $(S_SRC:.S=.o)

.PHONY: all run debug run-vbe iso gui clean

all: $(KERNEL) $(DISK)

$(KERNEL): $(OBJ) linker.ld
	$(LD) $(LDFLAGS) $(OBJ) -o $@
	@echo "Built $(KERNEL)"

# --- user programs (crt0 provides _start and calls main) ---
UCFLAGS := --target=$(TARGET) -m32 -ffreestanding -nostdlib -fno-pic -fno-pie \
           -mno-sse -mno-mmx -mno-sse2 \
           -O2 -Iinclude -Iuser -Ikernel

user/crt0.o: user/crt0.S
	$(CC) --target=$(TARGET) -m32 -ffreestanding -Iinclude -c user/crt0.S -o $@

user/libc/%.o: user/libc/%.c user/libc.h
	$(CC) $(UCFLAGS) -c $< -o $@

# Depend on wm.h too: several apps (term, dock) share the window IPC struct, and
# a change to it must rebuild every client or the message sizes drift out of sync.
user/%.elf: user/%.c user/libc.h user/wm.h user/crt0.o $(LIBC_OBJ) user/user.ld
	$(CC) $(UCFLAGS) -c user/$*.c -o user/$*.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/$*.o $(LIBC_OBJ) -o $@

# The compositor/graphics code compiled for userspace (used by the windowserver).
user/gfx_u.o: kernel/gfx.c kernel/gfx.h kernel/font8x16.h
	$(CC) $(UCFLAGS) -c kernel/gfx.c -o $@
user/desktop_u.o: kernel/desktop.c kernel/desktop.h kernel/gfx.h
	$(CC) $(UCFLAGS) -c kernel/desktop.c -o $@
user/wm_u.o: user/wm.c user/wm.h kernel/gfx.h kernel/desktop.h
	$(CC) $(UCFLAGS) -c user/wm.c -o $@

# windowserver links the compositor objects in addition to libc.
user/wserver.elf: user/wserver.c user/wm.h user/libc.h user/crt0.o $(LIBC_OBJ) $(WM_OBJ) user/user.ld
	$(CC) $(UCFLAGS) -c user/wserver.c -o user/wserver.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/wserver.o $(WM_OBJ) $(LIBC_OBJ) -o $@

$(EMBEDDED): user/init.elf tools/bin2c.py
	python3 tools/bin2c.py user/init.elf user_elf > $(EMBEDDED)

# --- FAT32 disk image containing the user programs + a sample text file ---
$(DISK): $(USER_PROGS) user/poem.txt user/about.txt tools/mkfat32.py
	python3 tools/mkfat32.py $(DISK) INIT.ELF user/init.elf LOGGER.ELF user/logger.elf \
	    SH.ELF user/sh.elf HELLO.ELF user/hello.elf \
	    CAT.ELF user/cat.elf GREP.ELF user/grep.elf ORPHAN.ELF user/orphan.elf \
	    NETD.ELF user/netd.elf ECHOSRV.ELF user/echosrv.elf ECHOCLI.ELF user/echocli.elf \
	    SAVE.ELF user/save.elf WSERVER.ELF user/wserver.elf TERM.ELF user/term.elf \
	    DOCK.ELF user/dock.elf FILES.ELF user/files.elf VIEWER.ELF user/viewer.elf \
	    ABOUT.TXT user/about.txt POEM.TXT user/poem.txt WMSTRESS.ELF user/wmstress.elf \
	    SETTINGS.ELF user/settings.elf

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

# Boot into graphics: bring up the desktop via the Bochs/std-VGA VBE fallback
# (needs no extra tooling). `vbe` on the cmdline opts into the framebuffer path.
run-vbe: $(KERNEL) $(DISK)
	@echo "Hover inside the QEMU window to capture the mouse (Ctrl+Alt+G to toggle grab)."
	qemu-system-i386 $(GUI_DISPLAY) -kernel $(KERNEL) -serial stdio -m 64M \
	    -drive file=$(DISK),format=raw,if=ide -vga std -append vbe

# Build a GRUB rescue ISO (preferred "real boot": GRUB sets the Multiboot
# framebuffer, so the desktop comes up with no cmdline flag). Needs grub-mkrescue
# + xorriso installed. Boot: qemu-system-i386 -cdrom aurora.iso -m 64M \
#   -drive file=disk.img,format=raw,if=ide
iso: $(KERNEL) $(DISK)
	mkdir -p isodir/boot/grub
	cp $(KERNEL) isodir/boot/aurora.elf
	cp boot/grub.cfg isodir/boot/grub/grub.cfg
	grub-mkrescue -o aurora.iso isodir
	@echo "Built aurora.iso"

# One command for the GUI: build everything, make the GRUB ISO, and boot it in
# QEMU with the desktop. This is the "real boot" path (needs grub-mkrescue +
# xorriso + mtools). No GRUB tools? `make run-vbe` shows the same desktop using
# only QEMU (Bochs-VBE fallback).
# Put disk.img on primary master (index=0) and the ISO on the secondary CD
# drive (index=2). `-cdrom` before `-drive` can steal the master slot and the
# kernel then sees "no ATA disk", so wserver never starts (blank screen).
gui: iso
	@echo "Hover inside the QEMU window to capture the mouse (Ctrl+Alt+G to toggle grab)."
	qemu-system-i386 $(GUI_DISPLAY) -m 1024 -vga std -serial stdio \
	    -drive file=$(DISK),format=raw,if=ide,index=0,media=disk \
	    -drive file=aurora.iso,format=raw,if=ide,index=2,media=cdrom \
	    -boot order=d

# WSLg workaround: VNC server on localhost:5901 (no WSLg window needed).
.PHONY: gui-vnc
gui-vnc: iso
	@echo "Connect a VNC viewer to localhost:5901"
	qemu-system-i386 -display vnc=:1 -m 1024 -vga std -serial stdio \
	    -drive file=$(DISK),format=raw,if=ide,index=0,media=disk \
	    -drive file=aurora.iso,format=raw,if=ide,index=2,media=cdrom \
	    -boot order=d

# Render the desktop with the real kernel 2D code into a PNG (no QEMU/display
# needed) — a quick way to preview kernel/gfx.c + kernel/desktop.c.
SCREENSHOT := aurora_desktop.png
.PHONY: screenshot
screenshot:
	$(CC) -I. -Ikernel tools/render_desktop.c -o /tmp/aurora_render
	/tmp/aurora_render /tmp/aurora_desktop.ppm
	python3 tools/ppm2png.py /tmp/aurora_desktop.ppm $(SCREENSHOT)
	@echo "Wrote $(SCREENSHOT)"

# Render the window server / compositor scene (two overlapping app windows) to a
# PNG with the real kernel/userspace code — previews Phase 9.2 without a display.
.PHONY: screenshot-wm
screenshot-wm:
	$(CC) -I. -Ikernel -Iuser tools/render_wm.c -o /tmp/aurora_render_wm
	/tmp/aurora_render_wm /tmp/aurora_windows.ppm
	python3 tools/ppm2png.py /tmp/aurora_windows.ppm aurora_windows.png
	@echo "Wrote aurora_windows.png"

# Boot the REAL kernel headless in QEMU (VBE framebuffer path) and capture the
# live framebuffer to a PNG via the QEMU monitor — proves the GUI on actual
# hardware emulation without needing a display. `verify-gui` types into the
# Terminal first to also prove the keyboard pipeline.
.PHONY: live-shot verify-gui demo-focus demo-drag demo-close demo-dock demo-files demo-view demo-max demo-min demo-menu demo-settings stress
live-shot: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live.png
verify-gui: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_typed.png \
	    --keys h,e,l,l,o,spc,a,u,r,o,r,a
# Phase 9.3: move the pointer onto the back window, click to focus/raise it, then
# type into it -> proves PS/2 mouse + cursor + hit-test + click-to-focus.
demo-focus: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_focus.png \
	    --mouse "move:212,134;click" --keys f,o,c,u,s
# Phase 9.4/9.5: grab the front Terminal by its title bar, drag it, and release
# -> proves the window-drag state machine on a live framebuffer.
demo-drag: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_drag.png \
	    --mouse "move:-188,40;down;move:250,-150;up"
# Phase 9.5: click the front Terminal's red close button -> the window is
# destroyed and its app exits ([term] window N closed on the serial log).
demo-close: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_close.png \
	    --mouse "move:26,40;click"
# Phase 9.6: move onto the Dock's first icon (Terminal) and click it -> the Dock
# (a separate process) launches a new Terminal ([dock] ready + a new window).
demo-dock: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_dock.png \
	    --mouse "move:144,-324;click"
# Phase 9.7: click the Dock's Files icon -> the Finder opens and lists /disk;
# then double-click the TERM.ELF row -> the Finder exec's it (a Terminal appears).
# Proves the Dock -> Finder -> app chain and that the GUI browses the VFS.
demo-files: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_files.png \
	    --mouse "move:72,-324;click;wait:2;move:90,274;click;click;wait:2"
# Phase 9.8: open the Finder from the Dock, double-click ABOUT.TXT -> the Finder
# hands it to the Viewer, which open/read/renders the text; then PgDn scrolls it.
# Proves the full Dock -> Finder -> file -> Viewer chain and arrow/PgDn input.
demo-view: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_view.png \
	    --mouse "move:72,-324;click;wait:2;move:90,194;click;click;wait:2" \
	    --keys pgdn
# Phase 10.1: click the "Terminal" window's green (maximize) light -> the window
# server reallocs its surface to fill the screen and sends WM_RESIZE; the app
# redraws. (Its buttons at (200,150) are left of Terminal 2, so the target is
# unambiguous regardless of which window booted on top.)
demo-max: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_max.png \
	    --mouse "move:260,220;click;wait:1"
# Phase 10.1: click the "Terminal" window's yellow (minimize) light -> window-shade
# (collapse to the title bar); a second click would expand it again.
demo-min: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_min.png \
	    --mouse "move:278,220;click;wait:1"
# Phase 10.2: click the "Aurora" title in the menu bar -> the system menu drops
# down (About / Settings / Close All Windows / Shut Down), drawn by the window
# server itself. (Add ;move:-68,-33;click;wait:2 to also pick "About AuroraOS".)
demo-menu: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_menu.png \
	    --mouse "move:472,370;click"
# Phase 10.3: open the Aurora menu -> Settings, then pick the "Aurora Dark"
# wallpaper and the "Orange" accent. Settings writes /disk/settings.cfg and the
# window server re-reads it (WM_RELOAD_SETTINGS), so the desktop retheme is live.
demo-settings: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_settings.png \
	    --mouse "move:472,370;click;move:-68,-59;click;wait:2;move:-392,-207;click;wait:1;move:0,-128;click;wait:1"
# Stabilization audit: click the Dock's diagnostics icon (E) to run the window
# server stress / leak self-test; the serial log shows the heap top (brk) staying
# flat across 50 create/destroy cycles and a graceful window-table limit.
stress: $(KERNEL) $(DISK)
	python3 tools/screendump.py $(KERNEL) $(DISK) aurora_live_stress.png \
	    --mouse "move:0,-324;click;wait:6" --serial aurora_stress.log
	@echo "--- window-server stress / leak self-test (serial) ---"
	@grep -E "wmstress|wm\] stat" aurora_stress.log || echo "(no stress output captured)"

clean:
	rm -f $(OBJ) $(KERNEL) $(DISK) $(EMBEDDED) user/*.o user/*.elf user/libc/*.o
	rm -rf isodir aurora.iso
