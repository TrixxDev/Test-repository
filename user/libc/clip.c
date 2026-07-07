/* Shared-clipboard client helpers — see the declarations in wm.h.
 *
 * The window server owns one shared buffer (WM_CLIP_SIZE bytes) and hands its
 * shm id to each app in the WM_CREATE reply. An app maps it once and then reads
 * and writes it directly, so copy/paste is not limited to the IPC message size;
 * the server only tracks the current length (last writer wins). */
#include "libc.h"
#include "wm.h"

static char *g_buf;     /* mapped shared clipboard, or NULL if unavailable */
static int   g_wm;      /* window-server pid */

void clip_init(int wm, int clip_sid)
{
    g_wm = wm;
    g_buf = (clip_sid >= 0) ? (char *)shm_map(clip_sid) : 0;
}

/* Copy `len` bytes of `s` into the shared buffer and tell the server the length. */
void clip_set(const char *s, int len)
{
    if (!g_buf) return;
    if (len < 0) len = 0;
    if (len > WM_CLIP_SIZE) len = WM_CLIP_SIZE;
    for (int i = 0; i < len; i++) g_buf[i] = s[i];
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_CLIPBOARD_SET; r.x = len;
    msgsend(g_wm, &r, sizeof(r));
}

/* Ask the server for the current clipboard length; the reply arrives as a
 * WM_CLIPBOARD_GET message whose `x` is the length (read clip_data() then). */
void clip_request(void)
{
    if (!g_buf) return;
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_CLIPBOARD_GET;
    msgsend(g_wm, &r, sizeof(r));
}

const char *clip_data(void) { return g_buf; }
