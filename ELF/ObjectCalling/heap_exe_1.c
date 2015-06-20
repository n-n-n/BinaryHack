#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <malloc.h>
#include <unistd.h> // sysconf
#include <sys/mman.h> // mprotect
#include <errno.h>
double f(void) {
	//void *p = malloc(100);
	//if (NULL == p) return 0;
	//free(p);
  return 2.17;
}
typedef double (*FUNC)(void);

int allow_execution(const void* address, int size)
{
  int ret;
  long pagesize = (int)sysconf(_SC_PAGE_SIZE);
  extern int errno;
  char *p = (char*)((long)(address + pagesize - 1L) & ~(pagesize - 1L));
  printf("page size %ld\n", pagesize);

  ret = mprotect((char*)p, pagesize * 10L /*pagesize * 10L*/, PROT_READ|PROT_WRITE|PROT_EXEC);
  if (0 == ret) return 0;
  switch(errno) {
  case EACCES:
	  printf("指定されたアクセスをメモリに設定することができない。 これは、例えば ファイルを読み取り専用で mmap(2) しており、その領域に対して mprotect() を呼び出して PROT_WRITE に設定しようとした場合に発生する。\n");
	  break;
  case EFAULT:
	  printf("メモリがアクセス可能でない。\n");
	  break;
  case EINVAL:
	  printf("addr が有効なポインタでないか、 システムのページサイズの倍数でない。\n");
	  break;
  case ENOMEM:
	  printf("no memory\n");
	  break;
  default:
	  printf("mprotect:%d\n",ret);
	  break;
  }
  return -1;
}

int main()
{
  int ret = 0;
  long pagesize = (int)sysconf(_SC_PAGE_SIZE);
  int size = 1024;//
  //void *p = malloc(size);
  //void* p = memalign(pagesize, size); // boundary, size
  void* p = mmap(NULL, size, PROT_EXEC, 
		 MAP_PRIVATE | MAP_DENYWRITE, 3, 0);
  if (NULL == p){
    printf("memory error\n");
    return 0;
  }
  memcpy(p, f, size);

  if (0 == allow_execution(p, size)) {
    printf("call f():\nret = %f\n", ((FUNC)p)());
  }
  free(p);
  //ret = munmap(p, size);
  printf("ret:%d\n", ret);
  return 0;
}

