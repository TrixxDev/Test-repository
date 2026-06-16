/* AuroraOS first desktop (Phase 9.3 preview): a static wallpaper + top menu bar
 * + Dock, drawn straight with the 2D library. No window server yet — this is the
 * "does it look like an OS?" milestone. */
#pragma once
#include "gfx.h"

void desktop_render(gfx_surface_t *s);
