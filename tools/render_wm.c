/* Host renderer for the window server / compositor (Phase 9.2): builds a desktop
 * with two overlapping app windows, each rendered into its own surface, then
 * composites them by z-order with the real kernel/userspace code. Outputs a PPM.
 *
 *   cc -I. -Ikernel -Iuser tools/render_wm.c -o render && ./render out.ppm
 *
 * See the `screenshot-wm` Makefile target. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "gfx.h"
#include "kernel/gfx.c"
#include "kernel/desktop.c"
#include "user/wm.c"

static gfx_surface_t *make_surface(int w, int h)
{
    gfx_surface_t *s = malloc(sizeof(*s));
    s->pixels = calloc((size_t)w * h, 4);
    s->width = w; s->height = h; s->pitch = w * 4; s->bpp = 32;
    return s;
}

static void files_content(gfx_surface_t *s)
{
    gfx_clear(s, GFX_RGB(0xff, 0xff, 0xff));
    gfx_fill_rect(s, 0, 0, 116, s->height, GFX_RGB(0xf1, 0xf1, 0xf5));   /* sidebar */
    gfx_fill_rect(s, 116, 0, 1, s->height, GFX_RGB(0xdd, 0xdd, 0xe2));
    uint32_t ink = GFX_RGB(0x22, 0x22, 0x2a), dim = GFX_RGB(0x77, 0x77, 0x82);
    gfx_draw_text(s, 12, 14, "Favorites", dim);
    gfx_draw_text(s, 16, 38, "Desktop",   ink);
    gfx_draw_text(s, 16, 58, "Documents", ink);
    gfx_draw_text(s, 16, 78, "Disk",      ink);
    gfx_draw_text(s, 140, 14, "Disk", dim);
    const char *items[] = { "Documents", "Pictures", "Music", "poem.txt", "NOTE.TXT" };
    for (int i = 0; i < 5; i++)
        gfx_draw_text(s, 144, 40 + i * 22, items[i], ink);
}

static void terminal_content(gfx_surface_t *s)
{
    gfx_clear(s, GFX_RGB(0x1e, 0x1e, 0x28));
    uint32_t prompt = GFX_RGB(0x3a, 0xd0, 0x6a), out = GFX_RGB(0xe6, 0xe6, 0xee);
    const char *lines[] = {
        "aurora> id",                         "uid=1000 pid=7",
        "aurora> save /disk/NOTE.TXT hi",     "save: wrote 3 bytes to /disk/NOTE.TXT",
        "aurora> cat /disk/NOTE.TXT",         "hi",
        "aurora> echocli hello",              "[echocli] echo: hello",
        "aurora> _",
    };
    for (int i = 0; i < 9; i++) {
        uint32_t c = (lines[i][0] == 'a') ? prompt : out;   /* prompt lines start with "aurora" */
        gfx_draw_text(s, 12, 12 + i * 18, lines[i], c);
    }
}

int main(int argc, char **argv)
{
    const char *outp = (argc > 1) ? argv[1] : "aurora_windows.ppm";
    int W = 1024, H = 768;

    gfx_surface_t screen = { calloc((size_t)W * H, 4), W, H, W * 4, 32 };
    desktop_render(&screen);                 /* wallpaper + menu bar + dock */

    gfx_surface_t *files = make_surface(360, 240);
    gfx_surface_t *term  = make_surface(430, 250);
    files_content(files);
    terminal_content(term);

    window_t wf = { 1, 150, 110, 1, 1, "Aurora Files", files };
    window_t wt = { 2, 470, 300, 2, 1, "Terminal",     term  };
    window_t *wins[] = { &wf, &wt };
    wm_composite(&screen, wins, 2);

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
