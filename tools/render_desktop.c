/* Host renderer: draws the AuroraOS desktop with the real kernel 2D code
 * (kernel/gfx.c + kernel/desktop.c) into an off-screen 32-bpp buffer and writes
 * it as a PPM. Lets us preview/verify the desktop without a display or QEMU.
 *
 *   cc -I. -Ikernel tools/render_desktop.c -o render && ./render out.ppm
 *
 * See the `screenshot` target in the Makefile. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "gfx.h"
#include "kernel/gfx.c"
#include "kernel/desktop.c"

int main(int argc, char **argv)
{
    const char *out = (argc > 1) ? argv[1] : "aurora_desktop.ppm";
    int W = 1024, H = 768;

    uint8_t *px = calloc((size_t)W * H, 4);
    if (!px) return 1;
    gfx_surface_t s = { px, W, H, W * 4, 32 };
    desktop_render(&s);

    FILE *f = fopen(out, "wb");
    if (!f) { perror("open"); return 1; }
    fprintf(f, "P6\n%d %d\n255\n", W, H);
    for (int i = 0; i < W * H; i++) {
        uint32_t v = ((uint32_t *)px)[i];
        unsigned char rgb[3] = { (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF };
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
    free(px);
    fprintf(stderr, "render_desktop: wrote %s (%dx%d)\n", out, W, H);
    return 0;
}
