/* AuroraOS 2D graphics library — see gfx.h. Software rendering, 32-bpp. */
#include "gfx.h"
#include "font8x16.h"

static inline void put(gfx_surface_t *s, int x, int y, uint32_t color)
{
    if (x < 0 || y < 0 || x >= s->width || y >= s->height)
        return;
    *(uint32_t *)(s->pixels + (uint32_t)y * s->pitch + (uint32_t)x * 4) = color;
}

void gfx_clear(gfx_surface_t *s, uint32_t color)
{
    gfx_fill_rect(s, 0, 0, s->width, s->height, color);
}

/* Clip a rectangle to the surface; returns 0 if nothing is left. */
static int clip(gfx_surface_t *s, int *x, int *y, int *w, int *h)
{
    if (*x < 0) { *w += *x; *x = 0; }
    if (*y < 0) { *h += *y; *y = 0; }
    if (*x + *w > s->width)  *w = s->width  - *x;
    if (*y + *h > s->height) *h = s->height - *y;
    return (*w > 0 && *h > 0);
}

void gfx_fill_rect(gfx_surface_t *s, int x, int y, int w, int h, uint32_t color)
{
    if (!clip(s, &x, &y, &w, &h))
        return;
    for (int yy = 0; yy < h; yy++) {
        uint32_t *row = (uint32_t *)(s->pixels + (uint32_t)(y + yy) * s->pitch + (uint32_t)x * 4);
        for (int xx = 0; xx < w; xx++)
            row[xx] = color;
    }
}

void gfx_draw_rect(gfx_surface_t *s, int x, int y, int w, int h, uint32_t color)
{
    gfx_fill_rect(s, x, y, w, 1, color);
    gfx_fill_rect(s, x, y + h - 1, w, 1, color);
    gfx_fill_rect(s, x, y, 1, h, color);
    gfx_fill_rect(s, x + w - 1, y, 1, h, color);
}

void gfx_fill_circle(gfx_surface_t *s, int cx, int cy, int r, uint32_t color)
{
    for (int dy = -r; dy <= r; dy++)
        for (int dx = -r; dx <= r; dx++)
            if (dx * dx + dy * dy <= r * r)
                put(s, cx + dx, cy + dy, color);
}

void gfx_fill_round_rect(gfx_surface_t *s, int x, int y, int w, int h, int r, uint32_t color)
{
    if (r * 2 > w) r = w / 2;
    if (r * 2 > h) r = h / 2;
    if (r < 0) r = 0;

    for (int yy = 0; yy < h; yy++) {
        for (int xx = 0; xx < w; xx++) {
            int skip = 0;
            /* Each corner: outside its quarter-circle -> skip. */
            if (xx < r && yy < r) {                 /* top-left    */
                int dx = r - xx, dy = r - yy;
                if (dx * dx + dy * dy > r * r) skip = 1;
            } else if (xx >= w - r && yy < r) {     /* top-right   */
                int dx = xx - (w - r - 1), dy = r - yy;
                if (dx * dx + dy * dy > r * r) skip = 1;
            } else if (xx < r && yy >= h - r) {     /* bottom-left */
                int dx = r - xx, dy = yy - (h - r - 1);
                if (dx * dx + dy * dy > r * r) skip = 1;
            } else if (xx >= w - r && yy >= h - r) {/* bottom-right*/
                int dx = xx - (w - r - 1), dy = yy - (h - r - 1);
                if (dx * dx + dy * dy > r * r) skip = 1;
            }
            if (!skip)
                put(s, x + xx, y + yy, color);
        }
    }
}

static inline uint32_t lerp_rgb(uint32_t a, uint32_t b, int num, int den)
{
    int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
    int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
    int r = ar + (br - ar) * num / den;
    int g = ag + (bg - ag) * num / den;
    int bl = ab + (bb - ab) * num / den;
    return GFX_RGB(r, g, bl);
}

void gfx_fill_vgradient(gfx_surface_t *s, int x, int y, int w, int h,
                        uint32_t top, uint32_t bottom)
{
    if (h <= 0)
        return;
    for (int yy = 0; yy < h; yy++) {
        uint32_t c = lerp_rgb(top, bottom, yy, h > 1 ? h - 1 : 1);
        gfx_fill_rect(s, x, y + yy, w, 1, c);
    }
}

void gfx_blit(gfx_surface_t *s, int x, int y, const uint32_t *src, int sw, int sh)
{
    for (int yy = 0; yy < sh; yy++)
        for (int xx = 0; xx < sw; xx++)
            put(s, x + xx, y + yy, src[yy * sw + xx]);
}

void gfx_draw_char(gfx_surface_t *s, int x, int y, char c, uint32_t color)
{
    unsigned ch = (unsigned char)c;
    if (ch < FONT_FIRST || ch > FONT_LAST)
        ch = '?';
    const uint8_t *g = font8x16[ch - FONT_FIRST];
    for (int row = 0; row < FONT_H; row++) {
        uint8_t bits = g[row];
        for (int col = 0; col < FONT_W; col++)
            if (bits & (0x80 >> col))
                put(s, x + col, y + row, color);
    }
}

void gfx_draw_text(gfx_surface_t *s, int x, int y, const char *str, uint32_t color)
{
    int cx = x;
    for (; *str; str++) {
        if (*str == '\n') { y += FONT_H; cx = x; continue; }
        gfx_draw_char(s, cx, y, *str, color);
        cx += FONT_W;
    }
}

int gfx_text_width(const char *str)
{
    int n = 0;
    while (str[n]) n++;
    return n * FONT_W;
}
