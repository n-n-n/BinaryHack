#include <stdio.h>
/*
objcopy --readonly-text -I binary -O elf64-x86-64 -B i386:x86-64 test.txt test.o
*/
extern char _binary_test_txt_start[];
extern char _binary_test_txt_end[];
extern char _binary_test_txt_size[];
int main()
{
  int i;
  long size = (long)_binary_test_txt_size;
  const char* str = _binary_test_txt_start;
  printf("%d\n", size);
  for (i = 0 ; i <size; i++) {
    printf("%c (0x%02X)\n", str[i], str[i]);
  }
  return 0;
}
