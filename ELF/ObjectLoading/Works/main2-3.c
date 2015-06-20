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
    void* func;
} symbol_name_t;

symbol_name_t g_asymbolname[MAX_SYMBOL_NAME_NUM];
int g_num;
int g_hello_pos;
void* hso = NULL;

int search_symbol_index(const char* name)
{
    int i = 0;
    for (i = 0 ; i < g_num; i++) {
        if (0 == strcmp(name, g_asymbolname[i].name)) {
            return i;
        }
    }
    return -1;
}

void* get_function(int symbol_pos)
{
    /* remove memory protection */
    int pagesize = (int)sysconf(_SC_PAGESIZE);
    char* p = (char*)((long)symbol_pos & ~(pagesize -1L));
    mprotect(p, pagesize * 10L, PROT_READ | PROT_WRITE | PROT_EXEC);
    return (void*)symbol_pos;
}

int add_symbol(const char* name, int func)
{
    if (-1 == search_symbol_index(name)) {
        if (g_num < MAX_SYMBOL_NAME_NUM) {
            printf("add %s\n", name);
            strcpy(g_asymbolname[g_num].name, name);
            g_asymbolname[g_num].func = (void*)func;
            g_num++;
            return g_num - 1;
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

void reloc_file(unsigned char* file_o, bfd* abfd, asymbol** syms)
{
    asection* sect;
    arelent **loc;
    int size;
    int i;

    /* relocat onl executable codes */
    //  sect = bfd_get_section_by_name(abfd, ".text");
    sect = abfd->sections;
    while (sect) {
        size = bfd_get_reloc_upper_bound(abfd, sect);
        assert(size >= 0);

        loc = (arelent**)malloc(size);
        size = bfd_canonicalize_reloc(abfd, sect, loc, syms);
        assert(size >= 0);

        for (i = 0; i < size ;i++) {
            arelent *rel = loc[i];
            int *p = (int*)(file_o + abfd->origin + sect->filepos + rel->address);

            asymbol * sym = *rel->sym_ptr_ptr;
            const char *name = sym->name;

            /* relocate section */
            if ((sym->flags & BSF_SECTION_SYM) != 0) {
                printf("relocate section %s\n", name);
                asection *s = bfd_get_section_by_name(abfd, name);
                *p += (int)file_o + abfd->origin + s->filepos + rel->addend; 
            } else {
                /* relocate functions */
                int index = search_symbol_index(name);
                if (-1 == index) {
                    printf("relocate function %s\n", name);
                    *p += (int)dlsym(RTLD_DEFAULT, name);
                    if (rel->howto->pc_relative) *p -=(int)p;
                } else {
                    printf("relocate function (exp) %s\n", name);
                    *p += (int)g_asymbolname[index].func;
                    if (rel->howto->pc_relative) *p -=(int)p;
                }
            }
        }
        free(loc);
        sect = sect->next;
    }
}

void create_symbol_function_pos(char* file_o, bfd* abfd, asymbol** syms, int symnum)
{
    int i;
    for (i = 0; i < symnum; i++) {
        asymbol *sym = syms[i];
        const char *name = bfd_asymbol_name(sym);
        int value = bfd_asymbol_value(sym);
        symbol_info info;
        if (NULL == name || 0 == strlen(name) || '.' == name[0]) continue;
        bfd_get_symbol_info(abfd, sym, &info);
        if (!bfd_is_undefined_symclass(info.type)) {
            // defined
            if (name[0] != '_') {
                int symbol_pos = 0;
                symbol_pos = abfd->origin + sym->section->filepos + value;
                LOG("Found %s :0x%08X (relative), ", name, symbol_pos);
                symbol_pos += (int)file_o;
                LOG("Found %s :0x%08X\n", name, symbol_pos);
                add_symbol(name, symbol_pos);
            }
        }
    }
}

/* search symbol */
int get_symbol_pos(const char* symbol_name, 
                   bfd* abfd, asymbol** syms, int symnum, char* file_o)
{
    int i;
    int symbol_pos = 0;

    for (i = 0; i < symnum; i++) {
        asymbol *sym = syms[i];
        const char *name = bfd_asymbol_name(sym);
        if (NULL == name || 0 == strlen(name) || '.' == name[0]) continue;
        if (0 == strcmp(name, symbol_name)) {
            LOG("[INFO] %s\n", name);
            int value = bfd_asymbol_value(sym);
            symbol_pos = (int)file_o + abfd->origin + sym->section->filepos + value;
            LOG("Found %s :0x%08X\n", name, symbol_pos);
            break;
        }
    }
    return symbol_pos;
}

unsigned char* load_file(const char* file);

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
  create_symbol_function_pos(file_o, abfd, syms, symnum);
  reloc_file(file_o, abfd, syms);

  symbol_pos = get_symbol_pos("hello", 
			      abfd, syms, symnum, file_o);
  func = (void (*) ())(get_function(symbol_pos));
  func();
/*
  symbol_pos = get_symbol_pos("hello_someone", 
			      abfd, syms, symnum, file_o);
  func1 = (void (*) (const char*))(get_function(symbol_pos));
  func1("WORLD!");
*/
  free(syms);
  bfd_close(abfd);

  free(file_o);
  return 0;
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
