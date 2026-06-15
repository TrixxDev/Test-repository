/* cat: copy files (or stdin) to stdout. */
#include "libc.h"

int main(int argc, char **argv)
{
    char buf[512];

    if (argc < 2) {                 /* no args: copy stdin -> stdout */
        int n;
        while ((n = read(0, buf, sizeof(buf))) > 0)
            write(1, buf, n);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], 0);
        if (fd < 0) {
            fprintf(2, "cat: %s: not found\n", argv[i]);
            continue;
        }
        int n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            write(1, buf, n);
        close(fd);
    }
    return 0;
}
