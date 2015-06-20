#include <cstdio>

class Foo
{
public:
  Foo() {
    printf("Foo Creating\n");
  }
  ~Foo() {
    printf("Foo destroying\n");
  }
};

Foo foo;
int main()
{
  printf("main\n");
  return 0;
}
