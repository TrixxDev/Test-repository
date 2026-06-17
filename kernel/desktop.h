/* AuroraOS first desktop (Phase 9.3 preview): a static wallpaper + top menu bar
 * + Dock, drawn straight with the 2D library. No window server yet — this is the
 * "does it look like an OS?" milestone. */
#pragma once
#include "gfx.h"

void desktop_render(gfx_surface_t *s);

/* Theme: wallpaper 0=blue 1=dark 2=purple 3=green; accent 0=blue 1=orange
 * 2=purple 3=green. The windowserver sets these from /disk/settings.cfg. */
void     desktop_set_theme(int wallpaper, int accent);
uint32_t desktop_accent_color(void);

/* UI scale (percent, clamped to 100..200). The single source of truth for the
 * desktop's visual scale: the menu bar scales here, and wm.c / wserver.c read
 * desktop_scale() so window chrome + the system menu scale to match. Default
 * 100 (so the host PNG renderers, which never set it, are unaffected). */
void desktop_set_scale(int pct);
int  desktop_scale(void);
int  desktop_menubar_h(void);    /* the menu-bar height at the current scale */
