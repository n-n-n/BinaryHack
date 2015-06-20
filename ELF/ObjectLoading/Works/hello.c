#include <stdio.h>
#include <memory.h>
#include <stdlib.h>

static void foo() /* static function is allowed */
{
  printf("foo\n");
}

void hello()
{
  puts("hello");
  //puts("world!");
}

void hello_someone(const char* name)
{
  hello();
  foo();
  void *p = malloc(10);
  puts(name);
  free(p);
}
