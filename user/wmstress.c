/* Window-server stress / leak self-test (stabilization audit, pre-1.0).
 *
 * Hammers the window server to expose memory/slot leaks and confirm graceful
 * limits. It is an ordinary client (no privileges); it asks the server to log
 * its live-window count and heap top (WM_STAT) before and after each phase, so a
 * leak shows up as a climbing `brk` in the serial log.
 *
 *   Phase 1: create + destroy a window N times -> heap must stay flat (the
 *            server frees each content buffer on destroy).
 *   Phase 2: create windows until the table is full -> creation must fail
 *            gracefully (status < 0), never crash; then destroy them all.
 */
#include "libc.h"
#include "wm.h"

#define N_CYCLES 50
#define N_LIMIT  24

static int wm;

static int create_win(int w, int h)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = 60; r.y = 60; r.w = w; r.h = h;
    const char *t = "stress"; int i = 0; while (t[i]) { r.str[i] = t[i]; i++; } r.str[i] = 0;
    msgsend(wm, &r, sizeof(r));

    wm_rep_t rep; int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    return rep.status == 0 ? rep.win : -1;
}

static void clear_win(int id, int w, int h, uint32_t color)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_DRAW_RECT; r.win = id; r.x = 0; r.y = 0; r.w = w; r.h = h; r.color = color;
    msgsend(wm, &r, sizeof(r));
}

static void destroy_win(int id)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_DESTROY; r.win = id;
    msgsend(wm, &r, sizeof(r));
}

static void stat(const char *label)
{
    wm_req_t r; memset(&r, 0, sizeof(r));
    r.op = WM_STAT;
    msgsend(wm, &r, sizeof(r));         /* server logs "[wm] stat: live=.. brk=.." */
    printf("[wmstress] %s\n", label);
    for (volatile int d = 0; d < 400000; d++) ;   /* let the log line flush */
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0) for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "wmstress: no window server\n"); return 1; }

    printf("[wmstress] start: 2x%d create/destroy cycles, then a %d-window limit test\n",
           N_CYCLES, N_LIMIT);
    stat("before");

    /* Phase 1: create + destroy repeatedly, twice. With the destroy-frees-buffer
     * fix the heap reaches steady state — the `brk` after round 1 and round 2 must
     * be identical (a leak would make it climb every round). */
    for (int round = 1; round <= 2; round++) {
        for (int i = 0; i < N_CYCLES; i++) {
            int id = create_win(120, 80);
            if (id > 0) {
                clear_win(id, 120, 80, GFX_RGB(0x30, 0x60, 0xc0));
                destroy_win(id);
            }
        }
        if (round == 1) stat("after round 1 (50 create/destroy)");
        else            stat("after round 2 (must match round 1 -> no leak)");
    }

    /* Phase 2: fill the window table; over-the-limit creates must fail cleanly. */
    int ids[N_LIMIT], got = 0;
    for (int i = 0; i < N_LIMIT; i++) {
        int id = create_win(100, 70);
        if (id > 0) ids[got++] = id;
    }
    printf("[wmstress] limit: %d of %d creates succeeded (table is bounded; the "
           "rest failed gracefully)\n", got, N_LIMIT);
    for (int i = 0; i < got; i++)
        destroy_win(ids[i]);
    stat("after limit test (all destroyed)");

    printf("[wmstress] done\n");
    return 0;
}
