#define _GNU_SOURCE
#include <bfd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define LOG_OUT
#ifdef LOG_OUT
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

#define MAX_NAME_LEN (256)
#define MAX_SYMBOL_NAME_NUM (10)

typedef struct {
  char name[MAX_NAME_LEN];
  int value;
} symbol_name_t;

symbol_name_t g_symbol_name[MAX_SYMBOL_NAME_NUM];
int g_num;

int search_symbol_index(const char* name)
{
  int i = 0;
  for (i = 0 ; i < g_num; i++) {
    if (0 == strcmp(name, g_symbol_name[i].name)) {
      printf("found symbol %s\n", name);
	return i;
    }
  }
  return -1;
 }

void add_symbol(const char* name, int value)
{
  if (-1 == search_symbol_index(name)) {
    if (g_num < MAX_SYMBOL_NAME_NUM) {
      strcpy(g_symbol_name[g_num].name, name);
      g_symbol_name[g_num].value = value;
      g_num++;
    }
  }
}

void get_symbols(asymbol*** psyms, int* psymnum, bfd* abfd)
{
  long storage;
  storage = bfd_get_symtab_upper_bound(abfd);
  assert(storage >= 0);
  if (storage) *psyms = (asymbol**)malloc(storage);
  *psymnum = bfd_canonicalize_symtab(abfd, *psyms);
  assert(*psymnum >= 0);
  return;
}

unsigned char* load_file(const char* file)
{
  FILE* fp;
  int size = 0;
  unsigned char* file_o;

  fp = fopen(file, "rb");
  if (NULL == fp) {
    printf("%s not found\n", file);
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  file_o = (unsigned char*)malloc(size);
  fread(file_o, 1, size, fp);
  fclose(fp);

  return file_o;
}

void create_symbol_table(const char* file_o, bfd* abfd, asymbol**syms, int symnum) 
{
  int i;
  for (i = 0; i < symnum; i++) {
    asymbol *asym = syms[i];
    const char *name = bfd_asymbol_name(asym);
    int value = bfd_asymbol_value(asym);
    symbol_info info;

    if (NULL == name || 0 == strlen(name)) continue;
    if ('.' == name[0]) continue;
    bfd_get_symbol_info(abfd, asym, &info);
    if (bfd_is_undefined_symclass(info.type)) {
      LOG("[undefined symbol name] %s\n", name);
      continue;
    }
    LOG("[defined symbol name] %s\n", name);

    value += (int)(file_o + abfd->origin + asym->section->filepos);
    add_symbol(name, value);
  }
}

/* search symbol */
int get_symbol_pos(const char* symbol_name, 
		   bfd* abfd, asymbol** syms, int symnum)
{
  int i;
  int symbol_pos = 0;

  for (i = 0; i < symnum; i++) {
    asymbol *sym = syms[i];
    const char *name = bfd_asymbol_name(sym);
    LOG("[INFO] %s\n", name);
    if (0 == strcmp(name, symbol_name)) {
      int value = bfd_asymbol_value(sym);
      symbol_pos = abfd->origin + sym->section->filepos + value;
      LOG("Found %s :0x%08X\n", name, symbol_pos);
      break;
    }
  }
  return symbol_pos;
}

void reloc_file(unsigned char* file_o, bfd* abfd, asymbol** syms)
{
  asection* sect;
  int origin = (int)file_o + abfd->origin;
  /* relocate executable codes */
  sect = abfd->sections;

  while(sect)
  {
    arelent **loc;
    int size;
    int i;

    size = bfd_get_reloc_upper_bound(abfd, sect);
    assert(size >= 0);

    loc = (arelent**)malloc(size);
    size = bfd_canonicalize_reloc(abfd, sect, loc, syms);
    assert(size >= 0);

    for (i = 0; i < size ;i++) {
      arelent *rel = loc[i];
      int *p = (int*)(file_o + sect->filepos + rel->address);
      asymbol *sym;
      const char *name;

      if (!rel->sym_ptr_ptr || !(*rel->sym_ptr_ptr)) continue;

      sym = *rel->sym_ptr_ptr;
      name = sym->name;

      if (!name || !name[0]) continue;

      if ('.' == name[0]) { 
	if (0 == (sym->flags & BSF_SECTION_SYM)) continue;
	/* section */
	printf("found section: %s\n", name);
	asection *s = bfd_get_section_by_name(abfd, name);
	if (!s) continue;
	*p += origin + sect->filepos + rel->addend;
	//*p += (int)file_o + sect->filepos;
      } else {
	/* relocate functions */
	int index = search_symbol_index(name);
	if (-1 != index) {
	  //from syms
	  printf("relocate-function(syms):%s\n", name);

	  int pagesize = (int)sysconf(_SC_PAGESIZE);
	  char* ptr = (char*)((int)g_symbol_name[index].value & ~(pagesize - 1));
	   mprotect(ptr, pagesize * 10L, PROT_READ | PROT_WRITE | PROT_EXEC);
	   /*
	  void* ptr = (void*)(((int)g_symbol_name[index].value + 4095) & ~4095 - 4096);
	   int ret = mprotect(ptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
	  //	  *p += g_symbol_name[index].value;
	   printf("mprotect: ret=%d\n", ret);
	   */
	  *p = (int)g_symbol_name[index].value;
	  if (rel->howto->pc_relative) *p -=(int)p + 4;
	  {
	    void (*func)(); 
	    func = ptr;
	    func();
	  }
	} else {
	  printf("relocate-function: %s\n", name);
	  *p = (int)dlsym(RTLD_DEFAULT, name);
	  if (rel->howto->pc_relative) *p -=(int)p + 4;
	}
      }
    }
    free(loc);
    sect = sect->next;
  }
}

void* get_function(unsigned char* file_o, int symbol_pos)
{
  void *symbol = file_o + symbol_pos;
  /* remove memory protection */
  int pagesize = (int)sysconf(_SC_PAGESIZE);
  char* p = (char*)((long)symbol & ~(pagesize -1L));
  mprotect(p, pagesize * 10L, PROT_READ | PROT_WRITE | PROT_EXEC);
  return symbol;
}

int main()
{
  int ret;
  int symnum;
  bfd* abfd;
  asymbol** syms;
  int symbol_pos, symbol_size;
  int index;

  const char* file = "hello.o";
  unsigned char* file_o;
  file_o = load_file(file);
  void (*func)();
  void (*func1)(const char*);

  abfd = bfd_openr(file, NULL);
  assert(abfd);
  ret = bfd_check_format(abfd, bfd_object);
  assert(ret);

  if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
    assert(bfd_get_error() == bfd_error_no_error);
    /* no symbol */
    bfd_close(abfd);
    return 1;
  }

  get_symbols(&syms, &symnum, abfd);
  create_symbol_table(file_o, abfd, syms, symnum);
  reloc_file(file_o, abfd, syms);

  //index = search_symbol_index("hello");
  symbol_pos = g_symbol_name[index].value;
  func = (void*)(((int)g_symbol_name[index].value + 4095) & ~4095 - 4096);
  //symbol_pos = get_function(file_o, get_symbol_pos("hello", abfd, syms, symnum));
  //  func = (void (*) ())(symbol_pos);
  func();

  symbol_pos = get_symbol_pos("hello_someone", abfd, syms, symnum);
  func1 = (void (*) (const char*))(get_function(file_o, symbol_pos));
  func1("WORLD!");

  free(syms);
  bfd_close(abfd);

  free(file_o);
  return 0;
}
