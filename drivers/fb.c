#include "fb.h"
#include "gfx.h"
#include "desktop.h"
#include "paging.h"
#include "io.h"
#include "kio.h"

static gfx_surface_t screen;
static int active;

/* Map a framebuffer region (identity) and record it as the screen surface. */
static void use_framebuffer(uint32_t addr, uint32_t w, uint32_t h, uint32_t pitch)
{
    uint32_t size = pitch * h;
    for (uint32_t off = 0; off < size; off += 0x1000)
        vmm_map_page(addr + off, addr + off, PAGE_PRESENT | PAGE_WRITE);
    screen.pixels = (uint8_t *)addr;
    screen.width  = (int)w;
    screen.height = (int)h;
    screen.pitch  = (int)pitch;
    screen.bpp    = 32;
    active = 1;
}

/* ---- Bochs / QEMU "std" VGA VBE fallback (works under bare `qemu -kernel`) ---- */

#define VBE_DISPI_INDEX 0x01CE
#define VBE_DISPI_DATA  0x01CF
#define VBE_DISPI_ID    0
#define VBE_DISPI_XRES  1
#define VBE_DISPI_YRES  2
#define VBE_DISPI_BPP   3
#define VBE_DISPI_ENABLE 4
#define VBE_ENABLED     0x01
#define VBE_LFB         0x40

static void vbe_write(uint16_t idx, uint16_t val)
{
    outw(VBE_DISPI_INDEX, idx);
    outw(VBE_DISPI_DATA, val);
}

static uint16_t vbe_read(uint16_t idx)
{
    outw(VBE_DISPI_INDEX, idx);
    return inw(VBE_DISPI_DATA);
}

static uint32_t pci_cfg_read(int dev, int off)
{
    uint32_t addr = 0x80000000u | ((uint32_t)dev << 11) | ((uint32_t)(off & 0xFC));
    outl(0xCF8, addr);
    return inl(0xCFC);
}

/* Find the linear framebuffer BAR of a PCI display controller (class 0x03). */
static uint32_t find_vga_lfb(void)
{
    for (int dev = 0; dev < 32; dev++) {
        uint32_t id = pci_cfg_read(dev, 0x00);
        if ((id & 0xFFFF) == 0xFFFF)
            continue;
        uint32_t cls = pci_cfg_read(dev, 0x08);
        if (((cls >> 24) & 0xFF) == 0x03)               /* display controller */
            return pci_cfg_read(dev, 0x10) & 0xFFFFFFF0u;   /* BAR0 = LFB */
    }
    return 0;
}

static int vbe_setup(uint32_t w, uint32_t h)
{
    if ((vbe_read(VBE_DISPI_ID) & 0xFFF0) != 0xB0C0)
        return 0;                           /* no Bochs VBE present */
    uint32_t lfb = find_vga_lfb();
    if (!lfb)
        return 0;

    vbe_write(VBE_DISPI_ENABLE, 0);         /* disable while reconfiguring */
    vbe_write(VBE_DISPI_XRES, (uint16_t)w);
    vbe_write(VBE_DISPI_YRES, (uint16_t)h);
    vbe_write(VBE_DISPI_BPP, 32);
    vbe_write(VBE_DISPI_ENABLE, VBE_ENABLED | VBE_LFB);

    use_framebuffer(lfb, w, h, w * 4);      /* LFB is linear: pitch = w*4 */
    kprintf("[fb] Bochs VBE %ux%u x32 LFB=0x%x\n", w, h, lfb);
    return 1;
}

static int cmdline_has(const char *cl, const char *word)
{
    for (; *cl; cl++) {
        const char *a = cl, *b = word;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b)
            return 1;
    }
    return 0;
}

int fb_init(const multiboot_info_t *mb)
{
    /* 1. A framebuffer handed to us by the loader (e.g. GRUB Multiboot video). */
    if ((mb->flags & MULTIBOOT_FLAG_FB) &&
        mb->framebuffer_type == MULTIBOOT_FB_TYPE_RGB && mb->framebuffer_bpp == 32) {
        use_framebuffer((uint32_t)mb->framebuffer_addr, mb->framebuffer_width,
                        mb->framebuffer_height, mb->framebuffer_pitch);
        kprintf("[fb] Multiboot framebuffer %ux%u x32 at 0x%x\n",
                mb->framebuffer_width, mb->framebuffer_height,
                (uint32_t)mb->framebuffer_addr);
        return 1;
    }

    /* 2. Opt-in Bochs VBE fallback (`-append vbe`) for bare `qemu -kernel`.
     *    Gated on the cmdline so the default text boot is never affected. */
    if ((mb->flags & MULTIBOOT_FLAG_CMDLINE) && mb->cmdline &&
        cmdline_has((const char *)mb->cmdline, "vbe"))
        return vbe_setup(1024, 768);

    return 0;
}

void fb_draw_desktop(void)
{
    if (active)
        desktop_render(&screen);
}
