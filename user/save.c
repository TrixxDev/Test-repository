/* save: write text to a file, creating/truncating it. (Demonstrates FS write.)
 *
 *   save <path> [text...]
 *
 * e.g. `save /disk/NOTE.TXT hello aurora` then `cat /disk/NOTE.TXT`. */
#include "libc.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(2, "usage: save <path> [text...]\n");
        return 1;
    }

    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        fprintf(2, "save: cannot open %s\n", argv[1]);
        return 1;
    }

    char buf[256];
    int n = 0;
    for (int i = 2; i < argc; i++) {
        const char *w = argv[i];
        while (*w && n < (int)sizeof(buf) - 1)
            buf[n++] = *w++;
        if (i + 1 < argc && n < (int)sizeof(buf) - 1)
            buf[n++] = ' ';
    }
    if (n < (int)sizeof(buf))
        buf[n++] = '\n';

    int w = write(fd, buf, n);
    close(fd);
    if (w < 0) {
        fprintf(2, "save: write failed\n");
        return 1;
    }
    printf("save: wrote %d bytes to %s\n", w, argv[1]);
    return 0;
}
