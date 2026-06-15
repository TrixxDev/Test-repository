/* A small program that prints its arguments, to show argv passing via exec. */
#include "ulib.h"

int main(int argc, char **argv)
{
    uputs("HELLO.ELF running in ring 3.\n");
    uputint("  argc", argc);
    for (int i = 0; i < argc; i++) {
        uputs("  arg: ");
        uputs(argv[i]);
        uputs("\n");
    }
    return 0;
}
