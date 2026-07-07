/* Host renderer for the window server (Phase 9.2): drives the real wm_state core
 * (user/wm.c) exactly as the windowserver daemon does — create windows, draw into
 * their surfaces, present — and writes the composited screen as a PPM. Verifies
 * the window-server logic + compositor without QEMU.
 *
 *   cc -I. -Ikernel -Iuser tools/render_wm.c -o render && ./render out.ppm
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "gfx.h"
#include "kernel/gfx.c"
#include "kernel/desktop.c"
#include "user/wm.c"

int main(int argc, char **argv)
{
    const char *outp = (argc > 1) ? argv[1] : "aurora_windows.ppm";
    int W = 1024, H = 768;
    gfx_surface_t screen = { calloc((size_t)W * H, 4), W, H, W * 4, 32 };

    wm_state_t st;
    wm_state_init(&st);

    /* "Aurora Files" window (the windowserver allocates each content surface). */
    int files = wm_create(&st, 150, 110, 360, 240, "Aurora Files",
                          calloc((size_t)360 * 240, 4), 0, 1, 0);
    wm_clear(&st, files, GFX_RGB(0xff, 0xff, 0xff));
    wm_draw_rect(&st, files, 0, 0, 116, 240, GFX_RGB(0xf1, 0xf1, 0xf5));
    wm_draw_rect(&st, files, 116, 0, 1, 240, GFX_RGB(0xdd, 0xdd, 0xe2));
    wm_draw_text(&st, files, 12, 14, "Favorites", GFX_RGB(0x77, 0x77, 0x82));
    wm_draw_text(&st, files, 16, 38, "Desktop",   GFX_RGB(0x22, 0x22, 0x2a));
    wm_draw_text(&st, files, 16, 58, "Documents", GFX_RGB(0x22, 0x22, 0x2a));
    wm_draw_text(&st, files, 16, 78, "Disk",      GFX_RGB(0x22, 0x22, 0x2a));
    const char *items[] = { "Documents", "Pictures", "Music", "poem.txt", "NOTE.TXT" };
    for (int i = 0; i < 5; i++)
        wm_draw_text(&st, files, 144, 40 + i * 22, items[i], GFX_RGB(0x22, 0x22, 0x2a));

    /* "Terminal" window — same content the term.c app sends over IPC. */
    int term = wm_create(&st, 300, 210, 430, 200, "Terminal",
                         calloc((size_t)430 * 200, 4), 0, 1, 0);
    wm_draw_rect(&st, term, 0, 0, 430, 200, GFX_RGB(0x1e, 0x1e, 0x28));
    const char *lines[] = { "AuroraOS Terminal", "aurora> id", "uid=1000 pid=9",
                            "aurora> hello", "Hello AuroraOS", "aurora> _" };
    uint32_t col[] = { GFX_RGB(0xa8,0xb0,0xff), GFX_RGB(0x3a,0xd0,0x6a), GFX_RGB(0xe6,0xe6,0xee),
                       GFX_RGB(0x3a,0xd0,0x6a), GFX_RGB(0xe6,0xe6,0xee), GFX_RGB(0x3a,0xd0,0x6a) };
    for (int i = 0; i < 6; i++)
        wm_draw_text(&st, term, 12, 14 + i * 20, lines[i], col[i]);

    wm_present(&st, &screen);    /* desktop + windows by z-order, to the screen */

    FILE *f = fopen(outp, "wb");
    fprintf(f, "P6\n%d %d\n255\n", W, H);
    for (int i = 0; i < W * H; i++) {
        uint32_t v = ((uint32_t *)screen.pixels)[i];
        unsigned char rgb[3] = { (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF };
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
    fprintf(stderr, "render_wm: wrote %s (%dx%d)\n", outp, W, H);
    return 0;
}
