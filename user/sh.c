/* AuroraOS shell: the first interactive userland process.
 *
 *   loop: print prompt -> read line -> tokenize -> (builtin | fork+exec) -> wait
 *
 * External commands NAME are resolved to /disk/NAME.ELF (upper-cased). A
 * trailing '&' runs the command in the background (no wait). */
#include "ulib.h"

#define LINE_MAX 128
#define ARG_MAX  16

static int readline(char *buf, int max)
{
    int n = 0;
    while (n < max - 1) {
        char c;
        int r = sys_read(0, &c, 1);
        if (r <= 0)
            continue;
        if (c == '\n')
            break;
        if (c == '\b') {              /* simple line editing */
            if (n > 0)
                n--;
            continue;
        }
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
        while (*p == ' ')
            *p++ = '\0';
        if (!*p)
            break;
        argv[argc++] = p;
        while (*p && *p != ' ')
            p++;
    }
    argv[argc] = 0;
    return argc;
}

/* Build "/disk/NAME.ELF" from a command name (upper-cased). */
static void resolve_path(char *out, const char *name)
{
    const char *prefix = "/disk/";
    int p = 0;
    while (prefix[p]) { out[p] = prefix[p]; p++; }
    int i = 0;
    while (name[i]) {
        char c = name[i++];
        if (c >= 'a' && c <= 'z')
            c -= 32;
        out[p++] = c;
    }
    const char *suffix = ".ELF";
    int s = 0;
    while (suffix[s])
        out[p++] = suffix[s++];
    out[p] = '\0';
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    uputs("\nAuroraOS shell.  builtins: help, exit.  '<name> [args] [&]' runs /disk/NAME.ELF\n");

    char line[LINE_MAX];
    char *av[ARG_MAX];

    for (;;) {
        uputs("aurora> ");

        if (readline(line, sizeof(line)) == 0)
            continue;

        int ac = tokenize(line, av, ARG_MAX);
        if (ac == 0)
            continue;

        if (ustreq(av[0], "exit")) {
            uputs("bye\n");
            return 0;
        }
        if (ustreq(av[0], "help")) {
            uputs("builtins: help, exit. anything else runs /disk/<NAME>.ELF\n");
            continue;
        }

        int background = 0;
        if (ustreq(av[ac - 1], "&")) {
            background = 1;
            av[--ac] = 0;
        }

        char path[64];
        resolve_path(path, av[0]);

        int pid = sys_fork();
        if (pid == 0) {
            sys_exec(path, av);
            uputs("sh: command not found: ");
            uputs(av[0]);
            uputs("\n");
            sys_exit(127);
        } else if (pid > 0) {
            if (background) {
                uputint("[bg] started pid", pid);
            } else {
                int status = -1;
                sys_wait(&status);
                uputint("[exit]", status);
            }
        } else {
            uputs("sh: fork failed\n");
        }
    }
}
