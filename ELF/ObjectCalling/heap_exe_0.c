#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h> // sysconf
#include <sys/mman.h> // mprotect

double f(void) {
  return 2.17;
}

void allow_execution(const void* address)
{
  int ret;
  long pagesize = (int)sysconf(_SC_PAGE_SIZE);
  //  char *p = (char*)((long)(address + pagesize - 1L) & ~(pagesize - 1L));
  printf("page size %d\n", pagesize);
  ret = mprotect(p, pagesize * 10L, PROT_READ|PROT_WRITE|PROT_EXEC);
  if (ret) {
    printf("mrotecte error %d\n", ret);
  }
}
typedef double (*FUNC)(void);
int main()
{
  int size = 1024;
  long pagesize = (int)sysconf(_SC_PAGE_SIZE);
  void *p = malloc(size);
  //void* p = (void*)memalign(pagesize, size); 
  if (NULL == p){
    printf("memory error\n");
  }
  memcpy(p, f, size);
  //  allow_execution(p);

  printf("call f():\nret = %f\n", ((FUNC)p)());
  //printf("call f():\nret = %f\n", ((double(*)(void))p)());
  return 0;
}
