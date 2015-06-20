#include <stdio.h>
/*
 g++はそのままではコンパイルできない
 */
void other(void (*funcp)())
{
  funcp();
}


int main()
{
  int a = 10;

  void inner(void) {
    printf("main's a is %d\n", a);
  }

  other(inner);
  return 0;
}
