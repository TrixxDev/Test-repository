# AuroraOS build system.
#
# Uses clang as a cross-compiler (no separate cross-toolchain needed) targeting
# bare-metal i686, and LLVM's lld as the linker. The result is a Multiboot1
# kernel that can be booted directly with `qemu-system-i386 -kernel`.

CC      := clang
LD      := ld.lld
TARGET  := i686-elf

INCLUDES := -Iinclude -Iarch/i386 -Idrivers -Ilib -Ikernel -Ifs -Inet

CFLAGS  := --target=$(TARGET) -m32 -ffreestanding -nostdlib \
           -fno-pic -fno-pie -fno-stack-protector \
           -mno-sse -mno-mmx -mno-sse2 \
           -std=gnu11 -O2 -g -Wall -Wextra -MMD -MP $(INCLUDES)

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
              user/cat.elf user/grep.elf user/orphan.elf user/nbtest.elf user/waittest.elf \
              user/sendwintest.elf \
              user/netd.elf user/echosrv.elf user/echocli.elf user/save.elf \
              user/wserver.elf user/term.elf user/dock.elf user/files.elf \
              user/viewer.elf user/wmstress.elf user/settings.elf user/fetch.elf \
              user/tlsconnect.elf user/httpsget.elf
LIBC_OBJ   := user/libc/string.o user/libc/printf.o user/libc/malloc.o user/libc/net.o user/libc/clip.o user/libc/http.o
# Portable graphics/compositor code, built for userspace and linked into wserver.
WM_OBJ     := user/gfx_u.o user/desktop_u.o user/wm_u.o

C_SRC := $(shell find kernel arch drivers lib fs net -name '*.c')
C_SRC := $(sort $(C_SRC) $(EMBEDDED))
S_SRC := $(shell find kernel arch drivers lib fs net -name '*.S')
OBJ   := $(C_SRC:.c=.o) $(S_SRC:.S=.o)

.PHONY: all run debug run-vbe iso gui clean

all: $(KERNEL) $(DISK)

$(KERNEL): $(OBJ) linker.ld
	$(LD) $(LDFLAGS) $(OBJ) -o $@
	@echo "Built $(KERNEL)"

# --- user programs (crt0 provides _start and calls main) ---
UCFLAGS := --target=$(TARGET) -m32 -ffreestanding -nostdlib -fno-pic -fno-pie \
           -mno-sse -mno-mmx -mno-sse2 \
           -O2 -MMD -MP -Iinclude -Iuser -Ikernel

# Auto-generated header dependencies (-MMD): a header edit now rebuilds every
# object that includes it. Without this, e.g. an x509.h struct change could leave
# stale .tlsu.o with a mismatched layout linked into the userspace TLS programs.
-include $(shell find . -name '*.d' 2>/dev/null)

# The portable crypto/tls/x509 trees compiled for userspace (freestanding, same
# sources as the host tests and the kernel-excluded build). tlsconnect links them.
TLS_U_SRC := crypto/sha256.c crypto/sha384.c crypto/hmac_sha256.c crypto/hkdf.c crypto/chacha20.c \
             crypto/poly1305.c crypto/chacha20poly1305.c crypto/x25519.c \
             crypto/bignum.c crypto/rsa.c crypto/rsa_pss.c crypto/mgf1.c \
             crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c \
             crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c \
             tls/record.c tls/record_reader.c tls/transcript.c tls/key_schedule.c \
             tls/handshake.c tls/client.c tls/conn.c tls/cert.c tls/trace.c tls/driver.c \
             x509/asn1.c x509/x509.c x509/verify_cert.c \
             compress/crc32.c compress/inflate.c compress/gzip.c \
             http2/frame.c http2/settings.c http2/data.c http2/hpack.c http2/headers.c http2/huffman.c \
             http2/hpack_table.c http2/hpack_decode.c http2/window_update.c
TLS_U_OBJ := $(TLS_U_SRC:.c=.tlsu.o)

%.tlsu.o: %.c
	$(CC) $(UCFLAGS) -Icrypto -Itls -Ix509 -Icompress -Ihttp2 -c $< -o $@

user/crt0.o: user/crt0.S
	$(CC) --target=$(TARGET) -m32 -ffreestanding -Iinclude -c user/crt0.S -o $@

user/libc/%.o: user/libc/%.c user/libc.h user/wm.h
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

# the Dock + Terminal render client-side into a shared surface (link the gfx lib).
user/dock.elf: user/dock.c user/wm.h user/libc.h user/crt0.o $(LIBC_OBJ) user/gfx_u.o user/user.ld
	$(CC) $(UCFLAGS) -c user/dock.c -o user/dock.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/dock.o user/gfx_u.o $(LIBC_OBJ) -o $@
user/term.elf: user/term.c user/wm.h user/libc.h user/crt0.o $(LIBC_OBJ) user/gfx_u.o user/user.ld
	$(CC) $(UCFLAGS) -c user/term.c -o user/term.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/term.o user/gfx_u.o $(LIBC_OBJ) -o $@
user/files.elf: user/files.c user/wm.h user/libc.h user/crt0.o $(LIBC_OBJ) user/gfx_u.o user/user.ld
	$(CC) $(UCFLAGS) -c user/files.c -o user/files.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/files.o user/gfx_u.o $(LIBC_OBJ) -o $@
user/viewer.elf: user/viewer.c user/wm.h user/libc.h user/crt0.o $(LIBC_OBJ) user/gfx_u.o user/user.ld
	$(CC) $(UCFLAGS) -c user/viewer.c -o user/viewer.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/viewer.o user/gfx_u.o $(LIBC_OBJ) -o $@
user/fetch.elf: user/fetch.c user/wm.h user/libc.h user/crt0.o $(LIBC_OBJ) user/gfx_u.o user/user.ld
	$(CC) $(UCFLAGS) -c user/fetch.c -o user/fetch.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/fetch.o user/gfx_u.o $(LIBC_OBJ) -o $@

# tlsconnect links the freestanding TLS stack (no WM/gfx). Needs the crypto/tls/
# x509 include paths for its own compile plus the embedded trust-root header.
user/tlsconnect.elf: user/tlsconnect.c user/tls_test_root.h user/libc.h user/crt0.o $(LIBC_OBJ) $(TLS_U_OBJ) user/user.ld
	$(CC) $(UCFLAGS) -Icrypto -Itls -Ix509 -c user/tlsconnect.c -o user/tlsconnect.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/tlsconnect.o $(TLS_U_OBJ) $(LIBC_OBJ) -o $@

# httpsget: the userspace HTTPS client (DNS -> TCP -> TLS 1.3 -> HTTP/1.1) over
# Aurora's own network stack. Same freestanding TLS stack as tlsconnect, plus the
# curated CA roots header. user/url.o (15.2) resolves redirect Location headers
# and is also a plain http:// transport for cross-scheme redirects. user/cookiejar.o
# (15.9) is the RFC 6265 cookie jar. user/base64.o (16.2) is for Basic auth.
user/url.o: user/url.c user/url.h
	$(CC) $(UCFLAGS) -c user/url.c -o user/url.o

user/cookiejar.o: user/cookiejar.c user/cookiejar.h
	$(CC) $(UCFLAGS) -c user/cookiejar.c -o user/cookiejar.o

user/base64.o: user/base64.c user/base64.h
	$(CC) $(UCFLAGS) -c user/base64.c -o user/base64.o

user/httpsget.elf: user/httpsget.c user/url.o user/cookiejar.o user/base64.o user/ca_roots.h user/libc.h user/crt0.o $(LIBC_OBJ) $(TLS_U_OBJ) user/user.ld
	$(CC) $(UCFLAGS) -Icrypto -Itls -Ix509 -Icompress -Ihttp2 -c user/httpsget.c -o user/httpsget.o
	$(LD) -m elf_i386 -no-pie -T user/user.ld user/crt0.o user/httpsget.o user/url.o user/cookiejar.o user/base64.o $(TLS_U_OBJ) $(LIBC_OBJ) -o $@

$(EMBEDDED): user/init.elf tools/bin2c.py
	python3 tools/bin2c.py user/init.elf user_elf > $(EMBEDDED)

# --- FAT32 disk image containing the user programs + a sample text file ---
$(DISK): $(USER_PROGS) user/poem.txt user/about.txt tools/mkfat32.py
	python3 tools/mkfat32.py $(DISK) INIT.ELF user/init.elf LOGGER.ELF user/logger.elf \
	    SH.ELF user/sh.elf HELLO.ELF user/hello.elf \
	    CAT.ELF user/cat.elf GREP.ELF user/grep.elf ORPHAN.ELF user/orphan.elf \
	    NBTEST.ELF user/nbtest.elf WAITTEST.ELF user/waittest.elf \
	    SENDWIN.ELF user/sendwintest.elf \
	    NETD.ELF user/netd.elf ECHOSRV.ELF user/echosrv.elf ECHOCLI.ELF user/echocli.elf \
	    SAVE.ELF user/save.elf WSERVER.ELF user/wserver.elf TERM.ELF user/term.elf \
	    DOCK.ELF user/dock.elf FILES.ELF user/files.elf VIEWER.ELF user/viewer.elf \
	    ABOUT.TXT user/about.txt POEM.TXT user/poem.txt WMSTRESS.ELF user/wmstress.elf \
	    SETTINGS.ELF user/settings.elf FETCH.ELF user/fetch.elf \
	    TLSCONN.ELF user/tlsconnect.elf HTTPSGET.ELF user/httpsget.elf

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
	    -drive file=$(DISK),format=raw,if=ide -vga std -append "vbe abs"

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
	    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	    -boot order=d

# WSLg workaround: VNC server on localhost:5901 (no WSLg window needed).
.PHONY: gui-vnc
gui-vnc: iso
	@echo "Connect a VNC viewer to localhost:5901"
	qemu-system-i386 -display vnc=:1 -m 1024 -vga std -serial stdio \
	    -drive file=$(DISK),format=raw,if=ide,index=0,media=disk \
	    -drive file=aurora.iso,format=raw,if=ide,index=2,media=cdrom \
	    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	    -boot order=d

# Verify the portable crypto/ primitives against known-answer vectors (NIST /
# RFC 4231), natively on the host — no QEMU, each primitive checked in isolation.
.PHONY: crypto-test
crypto-test:
	$(CC) -O2 -Icrypto tools/crypto_test.c crypto/sha256.c crypto/sha384.c crypto/hmac_sha256.c crypto/hkdf.c crypto/chacha20.c crypto/poly1305.c crypto/chacha20poly1305.c crypto/x25519.c -o /tmp/aurora_crypto_test
	/tmp/aurora_crypto_test

# Host-side TLS protocol tests (tls/ over the verified crypto/ primitives).
.PHONY: tls-test
tls-test:
	$(CC) -O2 -Icrypto -Itls -Ix509 tools/tls_test.c tls/record.c tls/record_reader.c tls/transcript.c tls/key_schedule.c tls/handshake.c tls/client.c tls/conn.c tls/driver.c tls/cert.c tls/trace.c x509/asn1.c x509/x509.c x509/verify_cert.c crypto/sha256.c crypto/hmac_sha256.c crypto/hkdf.c crypto/chacha20.c crypto/poly1305.c crypto/chacha20poly1305.c crypto/x25519.c crypto/bignum.c crypto/rsa.c crypto/rsa_pss.c crypto/mgf1.c crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/sha384.c crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c -o /tmp/aurora_tls_test
	/tmp/aurora_tls_test

# RFC 8448 trace runner: replays the published Simple 1-RTT Handshake through the
# tls/ engine and checks every derived value byte-for-byte against the RFC.
.PHONY: tls-trace-test
tls-trace-test:
	$(CC) -O2 -Icrypto -Itls -Ix509 tools/tls_trace_test.c tls/transcript.c tls/key_schedule.c tls/handshake.c tls/cert.c tls/client.c tls/trace.c x509/asn1.c x509/x509.c x509/verify_cert.c crypto/sha256.c crypto/hmac_sha256.c crypto/hkdf.c crypto/x25519.c crypto/rsa.c crypto/rsa_pss.c crypto/mgf1.c crypto/bignum.c crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/sha384.c crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c -o /tmp/aurora_tls_trace_test
	/tmp/aurora_tls_trace_test

# Host-side CRC-32 test (compress/ layer: gzip's trailer checksum).
.PHONY: crc32-test
crc32-test:
	$(CC) -O2 -Icompress tools/crc32_test.c compress/crc32.c -o /tmp/aurora_crc32_test
	/tmp/aurora_crc32_test

# Host-side DEFLATE test (compress/ layer: RFC 1951 decompression).
.PHONY: inflate-test
inflate-test:
	$(CC) -O2 -Icompress tools/inflate_test.c compress/inflate.c -o /tmp/aurora_inflate_test
	/tmp/aurora_inflate_test

# Host-side gzip container test (compress/ layer: RFC 1952 wrapping RFC 1951).
.PHONY: gzip-test
gzip-test:
	$(CC) -O2 -Icompress tools/gzip_test.c compress/gzip.c compress/inflate.c compress/crc32.c -o /tmp/aurora_gzip_test
	/tmp/aurora_gzip_test

# Host-side HTTP/2 frame layer test (http2/: RFC 7540 frame header + SETTINGS
# + DATA + full HPACK: encode (static table), Huffman decode, dynamic table,
# and full header-block decode).
.PHONY: h2-test
h2-test:
	$(CC) -O2 -Ihttp2 tools/h2_test.c http2/frame.c http2/settings.c http2/data.c http2/hpack.c http2/headers.c http2/huffman.c http2/hpack_table.c http2/hpack_decode.c http2/window_update.c -o /tmp/aurora_h2_test
	/tmp/aurora_h2_test

# Host-side HTTP/2 fuzz harness (Phase 17.5.1): random/malformed bytes into
# every http2/ decode entry point, checking both "never crashes" and
# "output invariants always hold" (see tools/h2_fuzz.c's own header comment).
# Fast plain build, many iterations -- a quick sweep, not the strong check
# below.
.PHONY: h2-fuzz
h2-fuzz:
	$(CC) -O2 -Ihttp2 tools/h2_fuzz.c http2/frame.c http2/settings.c http2/data.c http2/hpack.c http2/headers.c http2/huffman.c http2/hpack_table.c http2/hpack_decode.c http2/window_update.c -o /tmp/aurora_h2_fuzz
	/tmp/aurora_h2_fuzz

# Same fuzz harness, built with GCC's AddressSanitizer + UndefinedBehavior-
# Sanitizer (clang's own sanitizer runtime isn't installed in this
# environment, so this specifically uses gcc, unlike every other host
# target here) -- far stronger per-call checking (out-of-bounds reads/
# writes, use of uninitialized values, signed overflow, ...) at the cost of
# real per-iteration overhead, so fewer iterations by default. Override
# with `make h2-fuzz-san ITERS=2000000` for a longer, still-sanitized run.
SEED  ?= 0x4155524f
ITERS ?= 20000
.PHONY: h2-fuzz-san
h2-fuzz-san:
	gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Ihttp2 tools/h2_fuzz.c http2/frame.c http2/settings.c http2/data.c http2/hpack.c http2/headers.c http2/huffman.c http2/hpack_table.c http2/hpack_decode.c http2/window_update.c -o /tmp/aurora_h2_fuzz_san
	/tmp/aurora_h2_fuzz_san $(SEED) $(ITERS)

# The EXISTING fixed-vector h2-test suite, rebuilt with the same GCC
# sanitizers -- catches memory-safety bugs a passing/failing PASS-count
# alone can't reveal (this is exactly how Phase 17.5.1 found tools/
# h2_test.c's own check_hex() stack buffer overflow, silently present
# since 17.2.2's 98-byte C.5.3 vector: the test PASSED every run, since
# nothing observable depended on the corrupted stack bytes, until ASan's
# redzones caught it here).
.PHONY: h2-test-san
h2-test-san:
	gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Ihttp2 tools/h2_test.c http2/frame.c http2/settings.c http2/data.c http2/hpack.c http2/headers.c http2/huffman.c http2/hpack_table.c http2/hpack_decode.c http2/window_update.c -o /tmp/aurora_h2_test_san
	/tmp/aurora_h2_test_san

# Host-side X.509 / PKI tests (x509/ layer: ASN.1 DER reader, certificate parse).
.PHONY: x509-test
x509-test:
	$(CC) -O2 -Ix509 -Icrypto tools/x509_test.c x509/asn1.c x509/x509.c x509/verify_cert.c crypto/sha256.c crypto/sha384.c crypto/bignum.c crypto/rsa.c crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c -o /tmp/aurora_x509_test
	/tmp/aurora_x509_test

# Host-side RSA / big-integer math tests (crypto/ layer: pure math, no ASN.1).
.PHONY: rsa-test
rsa-test:
	$(CC) -O2 -Icrypto tools/rsa_test.c crypto/bignum.c crypto/rsa.c crypto/rsa_pss.c crypto/mgf1.c crypto/sha256.c -o /tmp/aurora_rsa_test
	/tmp/aurora_rsa_test

# Host-side P-256 low-level math tests (crypto/ layer: field mod p + scalar mod n,
# no curve/ECDSA yet).
.PHONY: p256-test
p256-test:
	$(CC) -O2 -Icrypto -Itools tools/p256_test.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/bignum.c -o /tmp/aurora_p256_test
	/tmp/aurora_p256_test

# Host-side P-384 field (mod p) + scalar (mod n) arithmetic vs Python KATs.
.PHONY: p384-test
p384-test:
	$(CC) -O2 -Icrypto -Itools tools/p384_test.c crypto/p384_field.c crypto/p384_scalar.c crypto/bignum.c -o /tmp/aurora_p384_test
	/tmp/aurora_p384_test

# Host-side ECDSA-P256-SHA256 verification against the official Wycheproof vectors.
.PHONY: ecdsa-test
ecdsa-test:
	$(CC) -O2 -Icrypto -Itools tools/ecdsa_test.c crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/bignum.c crypto/sha256.c -o /tmp/aurora_ecdsa_test
	/tmp/aurora_ecdsa_test

# Host-side ECDSA-P384-SHA384 verification against the official Wycheproof vectors.
.PHONY: ecdsa384-test
ecdsa384-test:
	$(CC) -O2 -Icrypto -Itools tools/ecdsa384_test.c crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c crypto/bignum.c crypto/sha384.c -o /tmp/aurora_ecdsa384_test
	/tmp/aurora_ecdsa384_test

# Host-side URL parse/resolve test (user/url.c: RFC 3986 reference resolution
# used to follow HTTP redirects, 15.2). Pure data, no networking.
.PHONY: url-test
url-test:
	$(CC) -O2 -Iuser tools/url_test.c user/url.c -o /tmp/aurora_url_test
	/tmp/aurora_url_test

# Host-side cookie jar test (user/ layer: RFC 6265, no network).
.PHONY: cookiejar-test
cookiejar-test:
	$(CC) -O2 -Iuser tools/cookiejar_test.c user/cookiejar.c -o /tmp/aurora_cookiejar_test
	/tmp/aurora_cookiejar_test

# Host-side base64 test (user/ layer: RFC 4648, for HTTP Basic auth).
.PHONY: base64-test
base64-test:
	$(CC) -O2 -Iuser tools/base64_test.c user/base64.c -o /tmp/aurora_base64_test
	/tmp/aurora_base64_test

# Host-side trust-store coverage test (user/ca_roots.h, generated by
# tools/gen_ca_roots.py, Phase 15.5): parse every root, verify each one's own
# signature with Aurora's own crypto, and enforce a minimum RSA/EC coverage
# floor so a bad regeneration can't silently drop a key-type family.
.PHONY: ca-roots-test
ca-roots-test:
	$(CC) -O2 -Ix509 -Icrypto -Iuser tools/ca_roots_test.c x509/asn1.c x509/x509.c x509/verify_cert.c crypto/sha256.c crypto/sha384.c crypto/bignum.c crypto/rsa.c crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c -o /tmp/aurora_ca_roots_test
	/tmp/aurora_ca_roots_test

# Host-side DNS cache test (net/dns.c: pure slot find/allocate/populate logic
# + TTL clamping, Phase 15.6). net/netcfg.c is linked for real (it's pure); the
# handful of hardware-touching calls are stubbed, same idea as dhcp-test.
.PHONY: dns-cache-test
dns-cache-test:
	$(CC) -O2 -Inet -Iinclude tools/dns_cache_test.c net/dns.c net/netcfg.c -o /tmp/aurora_dns_cache_test
	/tmp/aurora_dns_cache_test

# Host-side DHCP client test (net/dhcp.c: pure packet build/parse + lease-timer
# logic, RFC 2131/2132, Phase 15.3). net/netcfg.c is linked for real (it's pure);
# the handful of hardware-touching calls (udp_*/net_poll/net_now_ms/virtio_net_*/
# kprintf) are stubbed in tools/dhcp_test.c since nothing here calls the live
# dhcp_configure()/dhcp_tick() transaction path -- that's QEMU-only.
.PHONY: dhcp-test
dhcp-test:
	$(CC) -O2 -Inet -Iinclude -Idrivers tools/dhcp_test.c net/dhcp.c net/netcfg.c -o /tmp/aurora_dhcp_test
	/tmp/aurora_dhcp_test

# Live Internet TLS over Aurora's real engine, on the host, through the HTTPS
# CONNECT proxy (14.0.3a). NEEDS OUTBOUND NETWORK -- diagnostic, not part of the
# default suite. Drives a real TLS 1.3 handshake to CONNECTED and decrypts at
# least one real application_data record (NewSessionTicket).
#
# Defaults target this sandbox: github.com is reached through the egress proxy's
# TLS-inspecting terminator, so the trust anchor is the proxy CA (pre-installed at
# /root/.ccr/agent-proxy-ca.crt). Override for other environments, e.g.
#   make tls-live-test LIVE_HOST=example.com AURORA_TRUST_PEM=/path/root.pem
# With no AURORA_TRUST_PEM the harness falls back to the embedded ISRG Root X1.
LIVE_HOST ?= github.com
LIVE_PORT ?= 443
AURORA_TRUST_PEM ?= /root/.ccr/agent-proxy-ca.crt
.PHONY: tls-live-test
tls-live-test:
	$(CC) -O2 -Icrypto -Itls -Ix509 tools/tls_live_test.c tls/record.c tls/record_reader.c tls/transcript.c tls/key_schedule.c tls/handshake.c tls/client.c tls/conn.c tls/driver.c tls/cert.c tls/trace.c x509/asn1.c x509/x509.c x509/verify_cert.c crypto/sha256.c crypto/hmac_sha256.c crypto/hkdf.c crypto/chacha20.c crypto/poly1305.c crypto/chacha20poly1305.c crypto/x25519.c crypto/bignum.c crypto/rsa.c crypto/rsa_pss.c crypto/mgf1.c crypto/ecdsa.c crypto/p256_field.c crypto/p256_scalar.c crypto/p256_point.c crypto/sha384.c crypto/ecdsa384.c crypto/p384_field.c crypto/p384_scalar.c crypto/p384_point.c -o /tmp/aurora_tls_live_test
	AURORA_TRUST_PEM="$(AURORA_TRUST_PEM)" /tmp/aurora_tls_live_test $(LIVE_HOST) $(LIVE_PORT)

# Host-side TCP receive-ring test (net/rxring.c: the buffer behind tcp_recv).
# Pure data structure, no QEMU — proves space is reused so a connection is no
# longer capped at one bufferful over its whole lifetime.
.PHONY: rxring-test
rxring-test:
	$(CC) -O2 -Inet tools/rxring_test.c net/rxring.c -o /tmp/aurora_rxring_test
	/tmp/aurora_rxring_test

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
	rm -f $(OBJ) $(KERNEL) $(DISK) $(EMBEDDED) user/*.o user/*.elf user/libc/*.o $(TLS_U_OBJ)
	rm -f $(shell find . -name '*.d' 2>/dev/null)
	rm -rf isodir aurora.iso
