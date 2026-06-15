/* AuroraOS shell: interactive command loop with pipes.
 *
 *   prompt -> read line -> tokenize -> (builtin | command | a | b) -> wait
 *
 * External commands NAME resolve to /disk/NAME.ELF (upper-cased). A single
 * pipe 'a args | b args' is supported; a trailing '&' backgrounds a command. */
#include "libc.h"

#define LINE_MAX 128
#define ARG_MAX  16

static int readline(char *buf, int max)
{
    int n = 0;
    char c;
    while (n < max - 1) {
        if (read(0, &c, 1) <= 0)
            continue;
        if (c == '\n')
            break;
        if (c == '\b') { if (n > 0) n--; continue; }
        buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

static int tokenize(char *line, char **argv, int max)
{
    int argc = 0;
    char *p = line;
    while (*p && argc < max - 1) {
        while (*p == ' ') *p++ = '\0';
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ') p++;
    }
    argv[argc] = 0;
    return argc;
}

static void resolve_path(char *out, const char *name)
{
    const char *prefix = "/disk/";
    int p = 0;
    while (prefix[p]) { out[p] = prefix[p]; p++; }
    int i = 0;
    while (name[i]) {
        char c = name[i++];
        if (c >= 'a' && c <= 'z') c -= 32;
        out[p++] = c;
    }
    const char *suffix = ".ELF";
    for (int s = 0; suffix[s]; s++) out[p++] = suffix[s];
    out[p] = '\0';
}

static void exec_cmd(char **argv)   /* in child: never returns on success */
{
    char path[64];
    resolve_path(path, argv[0]);
    execv(path, argv);
    fprintf(2, "sh: command not found: %s\n", argv[0]);
    _exit(127);
}

/* Run "left | right". */
static void run_pipeline(char **left, char **right)
{
    int p[2];
    if (pipe(p) < 0) { fprintf(2, "sh: pipe failed\n"); return; }

    int pid1 = fork();
    if (pid1 == 0) {
        dup2(p[1], 1);
        close(p[0]); close(p[1]);
        exec_cmd(left);
    }
    int pid2 = fork();
    if (pid2 == 0) {
        dup2(p[0], 0);
        close(p[0]); close(p[1]);
        exec_cmd(right);
    }
    close(p[0]); close(p[1]);
    int st;
    wait(&st);
    wait(&st);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("\nAuroraOS shell.  builtins: help, exit.  pipes: 'a | b'.  bg: 'cmd &'\n");

    char line[LINE_MAX];
    char *av[ARG_MAX];

    for (;;) {
        printf("aurora> ");
        if (readline(line, sizeof(line)) == 0)
            continue;

        int ac = tokenize(line, av, ARG_MAX);
        if (ac == 0)
            continue;

        if (strcmp(av[0], "exit") == 0) { printf("bye\n"); return 0; }
        if (strcmp(av[0], "help") == 0) {
            printf("builtins: help, exit. pipes: a | b. else runs /disk/NAME.ELF\n");
            continue;
        }

        /* pipeline? */
        int pipe_at = -1;
        for (int i = 0; i < ac; i++)
            if (strcmp(av[i], "|") == 0) { pipe_at = i; break; }
        if (pipe_at > 0 && pipe_at < ac - 1) {
            av[pipe_at] = 0;
            run_pipeline(av, &av[pipe_at + 1]);
            continue;
        }

        int background = 0;
        if (strcmp(av[ac - 1], "&") == 0) { background = 1; av[--ac] = 0; }

        int pid = fork();
        if (pid == 0) {
            exec_cmd(av);
        } else if (pid > 0) {
            if (background) {
                printf("[bg] started pid %d\n", pid);
            } else {
                int status = -1;
                wait(&status);
                printf("[exit %d]\n", status);
            }
        } else {
            fprintf(2, "sh: fork failed\n");
        }
    }
}
