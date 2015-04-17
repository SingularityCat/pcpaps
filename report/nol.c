#include <stdio.h>

int main(int argc, char **argv)
{
    FILE *f;
    int lines = 0;
    int chr;

    if(argc > 1)
    {
        f = fopen(argv[1], "r");
    }
    else
    {
        f = stdin;
    }

    if(f == NULL)
    {
        printf("Error: %s - file not found.\n", argv[1]);
        return 1;
    }

    do
    {
        chr = fgetc(f);
        if(chr == '\n')
        {
            lines++;
        }
    } while(chr != -1);

    fclose(f);

    printf("Number of lines: %d\n", lines);
    return 0;
}

