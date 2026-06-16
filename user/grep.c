/* grep: print lines from stdin that contain a substring. */
#include "libc.h"

static int contains(const char *s, const char *pat)
{
    if (!*pat)
        return 1;
    for (; *s; s++) {
        const char *a = s, *b = pat;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b)
            return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *pat = (argc > 1) ? argv[1] : "";
    char line[256];
    int li = 0;
    char c;
    int n;

    while ((n = read(0, &c, 1)) > 0) {
        if (c == '\n') {
            line[li] = '\0';
            if (contains(line, pat)) {
                write(1, line, li);
                write(1, "\n", 1);
            }
            li = 0;
        } else if (li < (int)sizeof(line) - 1) {
            line[li++] = c;
        }
    }
    if (li > 0) {
        line[li] = '\0';
        if (contains(line, pat)) {
            write(1, line, li);
            write(1, "\n", 1);
        }
    }
    return 0;
}
