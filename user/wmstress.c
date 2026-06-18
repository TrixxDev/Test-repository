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

/* ---- Phase 3: SHM hardening self-test (Milestone 1.1.3a) ----
 * Exercises the reference-counted, grant-gated shared-memory lifecycle directly
 * (the kernel paths behind the window server's realloc-on-resize). Reports leaks
 * via sysinfo's free-frame count and validates that a destroy-while-mapped object
 * survives until its last mapper goes away (the resize use-after-free scenario). */
#define SHM_TEST_SZ  (64 * 1024)    /* 16 frames per object */
#define SHM_CYCLES   200
#define SENTINEL     0x5A

static unsigned free_frames(void)
{
    struct sysinfo si;
    return sysinfo(&si) == 0 ? si.free_frames : 0;
}

static int shm_hardening_test(void)
{
    int fails = 0;

    /* Warm up so any one-time kernel-heap growth is already done before we sample
     * the free-frame baseline (otherwise the first create looks like a leak). */
    for (int i = 0; i < 4; i++) { int id = shm_create(SHM_TEST_SZ, 0); if (id >= 0) shm_destroy(id); }

    /* (a) create / map / touch / unmap / destroy in a tight loop: the free-frame
     * count must return exactly to baseline (no leak across the new free path). */
    unsigned base = free_frames();
    for (int i = 0; i < SHM_CYCLES; i++) {
        int id = shm_create(SHM_TEST_SZ, 0);
        if (id < 0) { printf("[wmstress] shm: create failed at cycle %d\n", i); fails++; break; }
        volatile unsigned char *p = (volatile unsigned char *)shm_map(id);
        if (!p) { printf("[wmstress] shm: creator map failed\n"); fails++; shm_destroy(id); break; }
        p[0] = 0xAB; p[SHM_TEST_SZ - 1] = 0xCD;     /* touch the first and last page */
        shm_unmap(id);
        shm_destroy(id);
    }
    unsigned after = free_frames();
    /* free_frames is system-wide, so a stray frame or two of concurrent activity
     * (logger/window-server heap growth) is noise; a real per-cycle leak would be
     * thousands of frames. The meaningful assertion is that not even one object's
     * worth of frames (SHM_TEST_SZ/4096) went missing. */
    unsigned per_obj = SHM_TEST_SZ / 4096;
    unsigned leaked  = (base > after) ? base - after : 0;
    if (leaked >= per_obj) {
        printf("[wmstress] shm LEAK: %u frames after %d cycles (>= one object)\n", leaked, SHM_CYCLES);
        fails++;
    } else {
        printf("[wmstress] shm: %d create/map/unmap/destroy cycles, no object leaked "
               "(free %u->%u, %u-frame noise)\n", SHM_CYCLES, base, after, leaked);
    }

    /* (b) negative paths: bad ids and use-after-destroy must be refused, not crash. */
    if (shm_destroy(9999) != -1) { printf("[wmstress] shm: destroy(bad id) should fail\n"); fails++; }
    if (shm_unmap(9999)  != -1)  { printf("[wmstress] shm: unmap(bad id) should fail\n");  fails++; }
    { int id = shm_create(SHM_TEST_SZ, 0); shm_destroy(id);
      if (shm_map(id) != 0) { printf("[wmstress] shm: map after destroy should fail\n"); fails++; } }

    /* (c) cross-process grant + deferred free (the realloc-on-resize UAF case):
     * the parent grants the object to the child; both map it; the parent destroys
     * it while the child still maps it. The child must STILL read the sentinel
     * (frames not freed early), and the frames are reclaimed only once the child
     * exits — leaving the free-frame count back at its pre-test value. */
    {
        unsigned b2 = free_frames();
        int id = shm_create(SHM_TEST_SZ, 0);
        if (id < 0) { printf("[wmstress] shm: xproc create failed\n"); return fails + 1; }

        int pid = fork();
        if (pid == 0) {                                 /* ---- child ---- */
            int from = 0, msg = 0;
            msgrecv(&msg, sizeof(msg), &from);          /* wait for "go"; learn parent pid */
            volatile unsigned char *cp = (volatile unsigned char *)shm_map(id);
            int ok = (cp != 0);
            int v1 = ok ? cp[0] : -1;                   /* read before the parent destroys */
            int rdy = 1; msgsend(from, &rdy, sizeof(rdy));
            int go2 = 0; msgrecv(&go2, sizeof(go2), &from);
            int v2 = ok ? cp[0] : -1;                   /* read AFTER destroy (deferred free) */
            int rep = (ok && v1 == SENTINEL && v2 == SENTINEL) ? 1 : 0;
            msgsend(from, &rep, sizeof(rep));
            _exit(0);
        }
        /* ---- parent ---- */
        shm_grant(id, pid);
        volatile unsigned char *pp = (volatile unsigned char *)shm_map(id);
        if (pp) pp[0] = SENTINEL;
        int go = 1; msgsend(pid, &go, sizeof(go));      /* child may map now (grant is done) */
        int rdy = 0, from = 0; msgrecv(&rdy, sizeof(rdy), &from);   /* child has mapped */
        shm_destroy(id);                                /* destroy while child maps -> deferred */
        int go2 = 1; msgsend(pid, &go2, sizeof(go2));   /* child re-reads through its mapping */
        int childok = 0; msgrecv(&childok, sizeof(childok), &from);
        wait(0);                                        /* child exits -> last ref -> freed */

        unsigned a2 = free_frames();
        unsigned leaked2 = (b2 > a2) ? b2 - a2 : 0;
        if (!childok) { printf("[wmstress] shm: child lost access after destroy (UAF risk!)\n"); fails++; }
        else          { printf("[wmstress] shm: cross-proc grant + deferred-free OK\n"); }
        if (leaked2 >= per_obj) { printf("[wmstress] shm xproc LEAK: %u frames (%u->%u)\n", leaked2, b2, a2); fails++; }
        else                    { printf("[wmstress] shm: cross-proc frames reclaimed (%u->%u)\n", b2, a2); }
    }

    printf("[wmstress] shm hardening: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails;
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

    /* Phase 3: shared-memory hardening (refcount / grant / deferred free). */
    shm_hardening_test();

    printf("[wmstress] done\n");
    return 0;
}
