/* Terminal.app: the first interactive AuroraOS GUI app. It asks the window
 * server for a window, then runs an event loop: keys forwarded by the window
 * server are echoed into a tiny shell-style transcript, and the window is
 * redrawn (full repaint) after each keystroke. It is resizable: the window
 * server can maximize it, sending WM_RESIZE, and the column/row grid is
 * recomputed from the new size. Demonstrates the closed loop
 * keyboard -> windowserver -> app -> redraw -> framebuffer. */
#include "libc.h"
#include "wm.h"

#define DEF_W   460
#define DEF_H   240
#define ARG_MAX 16
#define MAXCOLS 128         /* fullscreen at 8px/char (1024/8) fits within this */
#define MAXROWS 48          /* fullscreen at 18px/row (768/18) fits within this */

static int wm;
static int win;
static int S = 100;                /* UI scale percent (queried from the system) */
static int W = DEF_W, H = DEF_H;    /* content size (updated on WM_RESIZE) */
static int COLS, ROWS;             /* derived character grid               */
static char hist[MAXROWS][MAXCOLS];
static int  nhist;
static char input[MAXCOLS];
static int  ilen;
static gfx_surface_t surf;          /* shared content surface (mapped from server) */
static int shm_id = -1;

/* All layout metrics scale with the UI scale S (8x16 font, 12px margins, history
 * at y=40 stepping 18 — each multiplied by S/100). At S=100 these are the originals. */
static int term_fw(void)  { int v = 8  * S / 100; return v < 1 ? 1 : v; }  /* font width  */
static int term_lh(void)  { int v = 18 * S / 100; return v < 1 ? 1 : v; }  /* line height */
static int term_mx(void)  { return 12 * S / 100; }                         /* left margin  */
static int term_top(void) { return 40 * S / 100; }                         /* first row y  */

/* Recompute the character grid from the pixel size and the UI scale. Keeps the
 * transcript within the new bounds. */
static void recompute_grid(void)
{
    COLS = (W - 2 * term_mx()) / term_fw();
    if (COLS < 8) COLS = 8;
    if (COLS > MAXCOLS - 1) COLS = MAXCOLS - 1;
    ROWS = (H - term_top()) / term_lh();
    if (ROWS < 2) ROWS = 2;
    if (ROWS > MAXROWS) ROWS = MAXROWS;

    if (nhist > ROWS - 1) {                 /* shrunk: keep the most recent lines */
        int drop = nhist - (ROWS - 1);
        for (int i = 0; i + drop < nhist; i++)
            memcpy(hist[i], hist[i + drop], MAXCOLS);
        nhist = ROWS - 1;
    }
    if (ilen > COLS - 10) ilen = COLS - 10;
    if (ilen < 0) ilen = 0;
}

static void set_str(wm_req_t *r, const char *s)
{
    int i = 0;
    while (s[i] && i < 47) { r->str[i] = s[i]; i++; }
    r->str[i] = '\0';
}

/* Client-side rendering: draw straight into the shared surface, then tell the
 * server to composite with a single WM_PRESENT (no per-element WM_DRAW_* IPC). */
static void repaint(void)
{
    if (!surf.pixels)
        return;
    int mx = term_mx(), top = term_top(), lh = term_lh();
    gfx_fill_rect(&surf, 0, 0, W, H, GFX_RGB(0x1e, 0x1e, 0x28));
    gfx_draw_text_s(&surf, mx, mx, "AuroraOS Terminal", GFX_RGB(0xa8, 0xb0, 0xff), S);
    for (int i = 0; i < nhist; i++)
        gfx_draw_text_s(&surf, mx, top + i * lh, hist[i], GFX_RGB(0xe6, 0xe6, 0xee), S);

    char line[MAXCOLS + 16];
    int p = 0;
    const char *prompt = "aurora> ";
    while (prompt[p]) { line[p] = prompt[p]; p++; }
    for (int i = 0; i < ilen && p < COLS + 8; i++) line[p++] = input[i];
    line[p++] = '_';
    line[p] = '\0';
    gfx_draw_text_s(&surf, mx, top + nhist * lh, line, GFX_RGB(0x3a, 0xd0, 0x6a), S);

    wm_req_t r;
    memset(&r, 0, sizeof(r));
    r.op = WM_PRESENT;
    msgsend(wm, &r, sizeof(r));
}

static void commit_line(void)
{
    if (nhist >= ROWS - 1) {                 /* scroll up one line */
        for (int i = 0; i < ROWS - 1; i++)
            memcpy(hist[i], hist[i + 1], MAXCOLS);
        nhist = ROWS - 2;
        if (nhist < 0) nhist = 0;
    }
    char *h = hist[nhist++];
    int p = 0;
    const char *prompt = "aurora> ";
    while (prompt[p] && p < COLS - 1) { h[p] = prompt[p]; p++; }
    for (int i = 0; i < ilen && p < COLS - 1; i++) h[p++] = input[i];
    h[p] = '\0';
    ilen = 0;
}

static int parse_int(const char *s)
{
    int v = 0, sign = 1;
    if (*s == '-') { sign = -1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v * sign;
}

/* ---- functional shell: run typed commands by fork/exec of /disk programs ---- */

/* Append one transcript line, scrolling the history up when full. */
static void push_line(const char *s)
{
    if (nhist >= ROWS - 1) {
        for (int i = 0; i < ROWS - 1; i++) memcpy(hist[i], hist[i + 1], MAXCOLS);
        nhist = ROWS - 2; if (nhist < 0) nhist = 0;
    }
    char *h = hist[nhist++];
    int p = 0;
    for (; s[p] && p < COLS - 1 && p < MAXCOLS - 1; p++) h[p] = s[p];
    h[p] = '\0';
}

/* Echo the committed prompt+input as a transcript line ("aurora> cmd"). */
static void echo_input(void)
{
    char l[MAXCOLS]; int p = 0;
    const char *pr = "aurora> ";
    while (pr[p] && p < MAXCOLS - 1) { l[p] = pr[p]; p++; }
    for (int i = 0; i < ilen && p < MAXCOLS - 1; i++) l[p++] = input[i];
    l[p] = '\0';
    push_line(l);
}

static int sh_tokenize(char *line, char **argv, int max)
{
    int argc = 0; char *p = line;
    while (*p && argc < max - 1) {
        while (*p == ' ') *p++ = '\0';
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ') p++;
    }
    argv[argc] = 0;
    return argc;
}

static void sh_resolve(char *out, const char *name)
{
    const char *pre = "/disk/"; int p = 0;
    while (pre[p]) { out[p] = pre[p]; p++; }
    for (int i = 0; name[i]; i++) {
        char c = name[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        out[p++] = c;
    }
    const char *suf = ".ELF";
    for (int s = 0; suf[s]; s++) out[p++] = suf[s];
    out[p] = '\0';
}

/* Drain a child's output pipe into the transcript, splitting on newlines and
 * wrapping over-long lines. */
static void render_stream(int fd)
{
    char buf[256], line[MAXCOLS]; int ll = 0, r;
    while ((r = read(fd, buf, sizeof buf)) > 0) {
        for (int i = 0; i < r; i++) {
            char c = buf[i];
            if (c == '\r') continue;
            if (c == '\n' || ll >= COLS - 1 || ll >= MAXCOLS - 1) {
                line[ll] = '\0'; push_line(line); ll = 0;
                if (c != '\n') line[ll++] = c;       /* keep the char that overflowed */
            } else {
                line[ll++] = c;
            }
        }
        repaint();                  /* stream output live instead of all-at-once at exit */
    }
    if (ll > 0) { line[ll] = '\0'; push_line(line); }
}

/* Run the current input line: built-ins handled in-process, everything else
 * fork/exec'd as /disk/NAME.ELF with stdout+stderr captured into the transcript.
 * The real text shell (user/sh.c) does the same resolution; this gives the GUI
 * terminal a working command loop instead of a passive transcript. */
static void run_command(void)
{
    echo_input();
    char cmd[MAXCOLS]; int n = 0;
    for (int i = 0; i < ilen && n < MAXCOLS - 1; i++) cmd[n++] = input[i];
    cmd[n] = '\0';
    ilen = 0;

    char *av[ARG_MAX];
    int ac = sh_tokenize(cmd, av, ARG_MAX);
    if (ac == 0) return;

    if (strcmp(av[0], "clear") == 0) { nhist = 0; return; }
    if (strcmp(av[0], "help") == 0) {
        push_line("builtins: help, id, clear.  else runs /disk/NAME.ELF");
        push_line("try: hello | id | cat /disk/POEM.TXT | httpsget <host>");
        return;
    }
    if (strcmp(av[0], "id") == 0) {
        char b[40]; int p = 0; const char *u = "uid=";
        while (u[p]) { b[p] = u[p]; p++; }
        int uid = getuid(); char t[12]; int k = 0; if (uid==0) t[k++]='0';
        while (uid) { t[k++] = '0' + uid % 10; uid /= 10; }
        while (k) b[p++] = t[--k];
        const char *pp = " pid="; for (int i=0; pp[i]; i++) b[p++]=pp[i];
        int pid = getpid(); k = 0; if (pid==0) t[k++]='0';
        while (pid) { t[k++] = '0' + pid % 10; pid /= 10; }
        while (k) b[p++] = t[--k];
        b[p] = '\0'; push_line(b);
        return;
    }

    repaint();                                   /* show the echoed command immediately */

    int pp[2];
    if (pipe(pp) < 0) { push_line("term: pipe failed"); return; }
    int pid = fork();
    if (pid == 0) {                              /* child: exec the program */
        char path[80]; sh_resolve(path, av[0]);
        dup2(pp[1], 1); dup2(pp[1], 2);
        close(pp[0]); close(pp[1]);
        execv(path, av);
        const char *e = "sh: command not found\n";
        int el = 0; while (e[el]) el++;
        write(1, e, el);
        _exit(127);
    }
    close(pp[1]);
    render_stream(pp[0]);                          /* blocks until the child closes it */
    close(pp[0]);
    int st; wait(&st);
}

int main(int argc, char **argv)
{
    /* Optional: argv = {prog, x, y, title}. Lets init stagger several windows. */
    int wx = 280, wy = 190;
    const char *title = "Terminal";
    if (argc > 2) { wx = parse_int(argv[1]); wy = parse_int(argv[2]); }
    if (argc > 3) title = argv[3];

    for (int t = 0; t < 40 && wm <= 0; t++) {
        wm = svc_lookup(WM_SERVICE);
        if (wm <= 0)
            for (volatile int d = 0; d < 200000; d++) ;
    }
    if (wm <= 0) { fprintf(2, "term: no window server\n"); return 1; }

    S = ui_scale();                 /* size the window + grid to the UI scale */
    W = DEF_W * S / 100;
    H = DEF_H * S / 100;
    recompute_grid();

    wm_req_t r;
    wm_rep_t rep;
    memset(&r, 0, sizeof(r));
    r.op = WM_CREATE; r.x = wx; r.y = wy; r.w = W; r.h = H;
    r.flags = WM_F_RESIZABLE | WM_F_SHM;        /* render client-side, zero-copy */
    set_str(&r, title);
    msgsend(wm, &r, sizeof(r));
    int from;
    for (;;) {
        int n = msgrecv(&rep, sizeof(rep), &from);
        if (n >= (int)sizeof(rep) && from == wm) break;
    }
    if (rep.status != 0 || rep.win <= 0 || rep.shm < 0) {
        fprintf(2, "term: create failed\n"); return 1;
    }
    win = rep.win;

    void *px = shm_map(rep.shm);                 /* map the shared content surface */
    if (!px) { fprintf(2, "term: shm map failed\n"); return 1; }
    shm_id = rep.shm;
    clip_init(wm, rep.clip);                      /* map the shared clipboard */
    surf.pixels = (uint8_t *)px;
    surf.width = W; surf.height = H; surf.pitch = W * 4; surf.bpp = 32;

    repaint();
    printf("[term] opened window %d\n", win);

    /* Event loop: WM_KEY = a typed key, WM_RESIZE = the server changed our size
     * (maximize/restore), WM_DESTROY = the close button was clicked. */
    for (;;) {
        wm_req_t k;
        int n = msgrecv(&k, sizeof(k), &from);
        if (n < (int)sizeof(k))
            continue;
        if (k.op == WM_DESTROY) {
            printf("[term] window %d closed\n", win);
            return 0;
        }
        if (k.op == WM_RESIZE) {        /* maximize/restore: the server resized us */
            if (k.flags >= 0) {         /* shared surface was reallocated: re-map it */
                void *px = shm_map(k.flags);
                if (!px)                /* map failed: keep the old surface, don't desync */
                    continue;
                if (shm_id >= 0 && shm_id != k.flags)
                    shm_unmap(shm_id);  /* drop our ref to the previous surface */
                shm_id = k.flags;
                surf.pixels = (uint8_t *)px;
            }
            W = k.w; H = k.h;
            surf.width = W; surf.height = H; surf.pitch = W * 4;
            recompute_grid();
            repaint();
            continue;
        }
        if (k.op == WM_SCALE) {         /* UI scale changed: re-flow at the new scale */
            S = ui_scale();
            recompute_grid();
            repaint();
            continue;
        }
        if (k.op == WM_CLIPBOARD_GET) { /* paste reply: insert clipboard (printable) */
            const char *cb = clip_data();
            int len = k.x;
            for (int i = 0; cb && i < len && ilen < COLS - 10 && ilen < MAXCOLS - 1; i++)
                if (cb[i] >= 32 && cb[i] < 127) input[ilen++] = cb[i];
            repaint();
            continue;
        }
        if (k.op != WM_KEY)
            continue;
        int c = k.x;
        if (c == 3) {                    /* Ctrl+C: copy the current input line */
            clip_set(input, ilen);
        } else if (c == 22) {            /* Ctrl+V: request a paste from the server */
            clip_request();
        }
        else if (c == '\n' || c == '\r') run_command();
        else if (c == '\b')              { if (ilen > 0) ilen--; }
        else if (c >= 32 && c < 127 && ilen < COLS - 10) input[ilen++] = (char)c;
        repaint();
    }
    return 0;
}
