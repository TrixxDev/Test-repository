/* AuroraOS 2D graphics library (Phase 9.1, minimal).
 *
 * Pure, portable software rendering over a linear 32-bpp surface. The same code
 * draws onto the real framebuffer (drivers/fb.c) and onto an off-screen buffer
 * on the host (so the desktop can be rendered to a PNG without a display).
 * Colors are 0x00RRGGBB; no alpha or fonts yet. */
#pragma once
#include <stdint.h>

/* Where a surface's pixels live. Today everything is plain RAM scanned out of the
 * linear framebuffer (SURFACE_RAM == 0, so a zero-initialized surface is RAM by
 * default). A future VirtIO GPU / GL backend tags its surfaces here, so the
 * compositor can branch on the backend instead of being rewritten. */
enum { SURFACE_RAM = 0, SURFACE_VIRTIO_GPU = 1, SURFACE_GL = 2 };

typedef struct {
    uint8_t *pixels;    /* base address of the pixel buffer            */
    int      width;     /* pixels                                      */
    int      height;    /* pixels                                      */
    int      pitch;     /* bytes per scanline                          */
    int      bpp;       /* bits per pixel (32 supported)               */
    int      backend;   /* SURFACE_RAM (default) / SURFACE_VIRTIO_GPU / SURFACE_GL */
} gfx_surface_t;

#define GFX_RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))

void gfx_clear(gfx_surface_t *s, uint32_t color);
void gfx_fill_rect(gfx_surface_t *s, int x, int y, int w, int h, uint32_t color);
void gfx_draw_rect(gfx_surface_t *s, int x, int y, int w, int h, uint32_t color);
void gfx_fill_round_rect(gfx_surface_t *s, int x, int y, int w, int h, int r, uint32_t color);
void gfx_fill_circle(gfx_surface_t *s, int cx, int cy, int r, uint32_t color);
void gfx_fill_vgradient(gfx_surface_t *s, int x, int y, int w, int h,
                        uint32_t top, uint32_t bottom);
void gfx_blit(gfx_surface_t *s, int x, int y, const uint32_t *src, int sw, int sh);

/* Text (8x16 bitmap font, ASCII 32..126; unknown chars render as '?'). */
void gfx_draw_char(gfx_surface_t *s, int x, int y, char c, uint32_t color);
void gfx_draw_text(gfx_surface_t *s, int x, int y, const char *str, uint32_t color);
int  gfx_text_width(const char *str);   /* width in pixels */

/* Scaled text: each 8x16 cell is nearest-neighbor scaled to a
 * (FONT_W*scale/100) x (FONT_H*scale/100) box. scale == 100 is pixel-identical
 * to the unscaled calls above (which are thin wrappers over these). Used by the
 * window server to grow chrome + menu-bar text for the UI-scale setting; app
 * content keeps the native (100%) calls until it is made scale-aware. */
void gfx_draw_char_s(gfx_surface_t *s, int x, int y, char c, uint32_t color, int scale);
void gfx_draw_text_s(gfx_surface_t *s, int x, int y, const char *str, uint32_t color, int scale);
int  gfx_text_width_s(const char *str, int scale);   /* scaled width in pixels */
int  gfx_font_w_s(int scale);                        /* FONT_W scaled by `scale` */
int  gfx_font_h_s(int scale);                        /* FONT_H scaled by `scale` */
