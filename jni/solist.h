#ifndef _SOLIST_H
#define _SOLIST_H

#include <elf.h>

#define SOINFO_NAME_LEN 128

#define SHT_ARM_EXIDEX 0x70000001
#define SHF_LINKORDER 0x80
#define SHT_FINI_ARRAY 15
#define SHT_INIT_ARRAY 14
#define PT_ARM_EXIDEX 0x70000001
#define FLAG_LINKER     0x00000010 // The linker itself
#define FLAG_EXE        0x00000004 // The main executable
#define ANDROID_ARM_LINKER

#ifndef DT_INIT_ARRAY
#define DT_INIT_ARRAY      25
#endif

#ifndef DT_FINI_ARRAY
#define DT_FINI_ARRAY      26
#endif

#ifndef DT_INIT_ARRAYSZ
#define DT_INIT_ARRAYSZ    27
#endif

#ifndef DT_FINI_ARRAYSZ
#define DT_FINI_ARRAYSZ    28
#endif

#ifndef DT_PREINIT_ARRAY
#define DT_PREINIT_ARRAY   32
#endif

#ifndef DT_PREINIT_ARRAYSZ
#define DT_PREINIT_ARRAYSZ 33
#endif

struct link_map {
    uintptr_t l_addr;
    char *l_name;
    uintptr_t l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
};
struct link_map_t {
    uintptr_t l_addr;
    char *l_name;
    uintptr_t l_ld;
    struct link_map_t *l_next;
    struct link_map_t *l_prev;
};

typedef void (*linker_function_t)();

typedef struct soinfo soinfo;

struct soinfo {
    char name[SOINFO_NAME_LEN];
    const Elf32_Phdr *phdr;
    size_t phnum;
    Elf32_Addr entry;
    Elf32_Addr base;
    unsigned size;

    uint32_t unused1;  // DO NOT USE, maintained for compatibility.

    Elf32_Dyn *dynamic;

    uint32_t unused2; // DO NOT USE, maintained for compatibility
    uint32_t unused3; // DO NOT USE, maintained for compatibility

    soinfo *next;
    unsigned flags;

    const char *strtab;
    Elf32_Sym *symtab;

    size_t nbucket;
    size_t nchain;
    unsigned *bucket;
    unsigned *chain;

    unsigned *plt_got;

    Elf32_Rel *plt_rel;
    size_t plt_rel_count;

    Elf32_Rel *rel;
    size_t rel_count;

    linker_function_t *preinit_array;
    size_t preinit_array_count;

    linker_function_t *init_array;
    size_t init_array_count;
    linker_function_t *fini_array;
    size_t fini_array_count;

    linker_function_t init_func;
    linker_function_t fini_func;

#if defined(ANDROID_ARM_LINKER)
    // ARM EABI section used for stack unwinding.
    unsigned *ARM_exidx;
    size_t ARM_exidx_count;
#elif defined(ANDROID_MIPS_LINKER)
    unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif

    size_t ref_count;
    struct link_map_t link_map;

    int constructors_called;

    // When you read a virtual address from the ELF file, add this
    // value to get the corresponding address in the process' address space.
    Elf32_Addr load_bias;

    int has_text_relocations;
    int has_DT_SYMBOLIC;

    void (*CallConstructors)();

    void (*CallDestructors)();

    void (*CallPreInitConstructors)();

    void (*CallArray)(const char *array_name, linker_function_t *functions, size_t count,
                   int reverse);

    void (*CallFunction)(const char *function_name, linker_function_t function);
};

#endif
