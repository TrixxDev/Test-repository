/* Demonstrates argv passing, libc printf and malloc/free. */
#include "libc.h"

int main(int argc, char **argv)
{
    printf("HELLO.ELF running in ring 3 (pid %d), argc=%d\n", getpid(), argc);
    for (int i = 0; i < argc; i++)
        printf("  argv[%d] = %s\n", i, argv[i]);

    char *m = (char *)malloc(64);
    strcpy(m, "  malloc/free works");
    printf("%s\n", m);
    free(m);
    return 0;
}
