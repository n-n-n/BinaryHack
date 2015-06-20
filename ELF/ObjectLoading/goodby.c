#include <stdio.h>
#include "hello.h"

int goodby()
{
    printf("goodby\n");
    return 1;
}
int goodby_someone(const char* name)
{
    printf("goodby %s\n", name);
    return 2;
}
