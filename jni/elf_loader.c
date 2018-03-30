#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <jni.h>
#include "solist.h"
#include <android/log.h>

#define LOG_TAG "white_knignt"
#define DL_ERR(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define PAGE_START(x)  ((x) & PAGE_MASK)//
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define MAYBE_MAP_FLAG(x, from, to)    (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
static unsigned bitmask[4096];
#define MARK(offset) \
    do { \
        bitmask[((offset) >> 12) >> 3] |= (1 << (((offset) >> 12) & 7)); \
    } while(0)
#define FLAG_LINKED     0x00000001
#define R_ARM_COPY       20
#define R_ARM_GLOB_DAT   21
#define R_ARM_JUMP_SLOT  22
#define R_ARM_RELATIVE   23
#define R_ARM_ABS32      2
#define R_ARM_REL32      3
#define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx segment */
#define PT_GNU_RELRO 0x6474e552
#define DT_FLAGS 30
#define DF_TEXTREL    0x00000004
#define DF_SYMBOLIC   0x00000002
enum RelocationKind {
    kRelocAbsolute = 0,
    kRelocRelative,
    kRelocCopy,
    kRelocSymbol,
    kRelocMax
};
struct linker_stats_t {
    int count[kRelocMax];
};

static struct linker_stats_t linker_stats;

static void count_relocation(enum RelocationKind kind) {
    ++linker_stats.count[kind];
}

static size_t phdr_num;
static Elf32_Phdr *phdr_table;
static Elf32_Phdr *loaded_phdr;
static void *load_start;
static Elf32_Addr load_bias;
Elf32_Ehdr *ehdr_main;
soinfo *handler;

static int checkMagicNum(Elf32_Ehdr *ehdr) {
    DL_ERR("begain check");
    if (ehdr->e_ident[0] != 0x7f) { return -1; }
    if (ehdr->e_ident[1] != 'E') { return -1; }
    if (ehdr->e_ident[2] != 'L') { return -1; }
    if (ehdr->e_ident[3] != 'F') { return -1; }
    return 0;
}

unsigned long getLibAddr() {
    unsigned long ret = 0;
    char name[] = "libnative-lib.so";
    char buf[4096], *temp;
    int pid;
    FILE *fp;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        puts("open failed");
        goto _error;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, name)) {
            temp = strtok(buf, "-");
            ret = strtoul(temp, NULL, 16);
            break;
        }
    }
    _error:
    fclose(fp);
    return ret;
}

size_t phdr_table_get_load_size(const Elf32_Phdr *phdr_table,
                                size_t phdr_count,
                                Elf32_Addr *out_min_vaddr,
                                Elf32_Addr *out_max_vaddr) {
    Elf32_Addr min_vaddr = 0xFFFFFFFFU;
    Elf32_Addr max_vaddr = 0x00000000U;

    int found_pt_load = 0;
    for (size_t i = 0; i < phdr_count; ++i) {
        const Elf32_Phdr *phdr = &phdr_table[i];
        //获取PT_LOAD 段，遍历两个PT_LOAD段取出最大地址和最小地址然后内存对齐，返回需要加载的内存大小
        DL_ERR("p_type is %d\n", phdr->p_type);
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = 1;

        if (phdr->p_vaddr < min_vaddr) {//取得最小的虚拟地址
            DL_ERR("min_vadrr is 0x%x\n", phdr->p_vaddr);
            min_vaddr = phdr->p_vaddr;
        }

        if ((phdr->p_vaddr + phdr->p_memsz) > max_vaddr) {//取得最大的虚拟地址
            DL_ERR("p_vaddr is 0x%x,p_memsz is 0x%x\n", phdr->p_vaddr, phdr->p_memsz);
            max_vaddr = (phdr->p_vaddr + phdr->p_memsz);
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0x00000000U;
    }

    min_vaddr = PAGE_START(min_vaddr);//保留以字节为单位的页面对齐大小
    max_vaddr = PAGE_END(max_vaddr);

    if (out_min_vaddr != NULL) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != NULL) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;//返回需要加载的内存大小
}

int LoadSegments(Elf32_Addr load_bias) {
    for (size_t i = 0; i < phdr_num; ++i) {
        const Elf32_Phdr *phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Segment addresses in memory.
        Elf32_Addr seg_start = phdr->p_vaddr + load_bias;//虚拟地址+偏移地址 =段的起始地址，通常load_bias_的值为0；
        DL_ERR("seg_start is 0x%x\n ", seg_start);
        Elf32_Addr seg_end = seg_start + phdr->p_memsz;//段的结尾地址
        DL_ERR("seg_end is 0x%x\n ", seg_end);
        Elf32_Addr seg_page_start = PAGE_START(seg_start);//页对齐，mmap要求页对齐
        DL_ERR("seg_page_start is 0x%x\n ", seg_page_start);
        Elf32_Addr seg_page_end = PAGE_END(seg_end);//页对齐
        DL_ERR("seg_page_end is 0x%x\n ", seg_page_end);

        Elf32_Addr seg_file_end = seg_start + phdr->p_filesz;
        DL_ERR("seg_file_end is 0x%x\n ", seg_file_end);

        // File offsets.
        Elf32_Addr file_start = phdr->p_offset;
        DL_ERR("file_start is 0x%x\n ", file_start);
        Elf32_Addr file_end = file_start + phdr->p_filesz;
        DL_ERR("file_end is 0x%x\n ", file_end);

        Elf32_Addr file_page_start = PAGE_START(file_start);//这里为什么需要对齐？
        DL_ERR("file_page_start is 0x%x\n ", file_page_start);
        Elf32_Addr file_length = file_end - file_page_start;
        DL_ERR("file_length is 0x%x\n ", file_length);
        if (file_length != 0) {
            void *seg_addr = mmap((void *) seg_page_start,
                                  file_length,
                                  PROT_WRITE | PROT_READ,
                                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                                  -1,
                                  0);
            if (seg_addr == MAP_FAILED) {
                DL_ERR("couldn't mmap1 \"%s\" segment %d: %s", 0, i, strerror(errno));
                return 0;
            }
            DL_ERR("mmap success seg_addr is 0x%x\n", seg_addr);
            memcpy(seg_addr, (const void *) (file_page_start + (Elf32_Addr) ehdr_main),
                   file_length);

            if (-1 == mprotect(seg_addr, file_length, PFLAGS_TO_PROT(phdr->p_flags))) {
                DL_ERR("couldn't mprotect \"%s\" segment %d: %s", i, strerror(errno));
                return 0;
            }
            DL_ERR("LoadSegments succeed!\n");
        }


        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
            memset((void *) seg_file_end, 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
        }
        seg_file_end = PAGE_END(seg_file_end);
        if (seg_page_end > seg_file_end) {
            void *zeromap = mmap((void *) seg_file_end,
                                 seg_page_end - seg_file_end,
                                 PFLAGS_TO_PROT(phdr->p_flags),
                                 MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                 -1,
                                 0);
            if (zeromap == MAP_FAILED) {
                return 0;
            }
        }
    }
    return 1;
}

int CheckPhdr(Elf32_Addr loaded) {
    const Elf32_Phdr *phdr_limit = phdr_table + phdr_num;
    Elf32_Addr loaded_end = loaded + (phdr_num * sizeof(Elf32_Phdr));
    for (Elf32_Phdr *phdr = phdr_table; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        Elf32_Addr seg_start = phdr->p_vaddr + load_bias;
        Elf32_Addr seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr = (Elf32_Phdr *) loaded;
            return 1;
        }
    }
    DL_ERR("loaded phdr  not in loadable segment");
    return 0;
}

int FindPhdr() {
    const Elf32_Phdr *phdr_limit = phdr_table + phdr_num;

    // If there is a PT_PHDR, use it directly.
    for (const Elf32_Phdr *phdr = phdr_table; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr(load_bias + phdr->p_vaddr);
        }
    }
    for (const Elf32_Phdr *phdr = phdr_table; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                Elf32_Addr elf_addr = load_bias + phdr->p_vaddr;
                const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *) (void *) elf_addr;
                Elf32_Addr offset = ehdr->e_phoff;
                return CheckPhdr((Elf32_Addr) ehdr + offset);
            }
            break;
        }
    }

    DL_ERR("can't find loaded phdr ");
    return 0;
}

static Elf32_Sym *soinfo_elf_lookup(soinfo *si, unsigned hash, const char *name) {
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    DL_ERR("SEARCH %s in %s@0x%08x %08x %d",
           name, si->name, si->base, hash, hash % si->nbucket);
    for (unsigned n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
        Elf32_Sym *s = symtab + n;
        if (strcmp(strtab + s->st_name, name)) continue;
        switch (ELF32_ST_BIND(s->st_info)) {
            case STB_GLOBAL:
            case STB_WEAK:
                if (s->st_shndx == SHN_UNDEF) {
                    continue;
                }
                DL_ERR("FOUND %s in %s (%08x) %d",
                       name, si->name, s->st_value, s->st_size);
                return s;
        }
    }

    return NULL;
}

static unsigned elfhash(const char *_name) {
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

static Elf32_Sym *soinfo_do_lookup(soinfo *si, const char *name, soinfo **lsi, soinfo *needed[]) {
    unsigned elf_hash = elfhash(name);
    Elf32_Sym *s = NULL;

    if (si != NULL) {

        s = soinfo_elf_lookup(si, elf_hash, name);
        if (s != NULL) {
            *lsi = si;
            goto done;
        }
        for (int i = 0; needed[i] != NULL; i++) {
            DL_ERR("%s: looking up %s in %s",
                   si->name, name, needed[i]->name);
            s = soinfo_elf_lookup(needed[i], elf_hash, name);
            if (s != NULL) {
                *lsi = needed[i];
                goto done;
            }
        }
    }
    done:
    if (s != NULL) {
        DL_ERR("si %s sym %s s->st_value = 0x%08x, "
                       "found in %s, base = 0x%08x, load bias = 0x%08x",
               si->name, name, s->st_value,
               (*lsi)->name, (*lsi)->base, (*lsi)->load_bias);
        return s;
    }
    return NULL;
}


static int soinfo_relocate(soinfo *si, Elf32_Rel *rel, unsigned count,
                           soinfo *needed[]) {
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    DL_ERR("systab is 0x%x,strtab is 0x%x,rel_count is 0x%x\n", symtab, strtab, count);
    Elf32_Sym *s;
    Elf32_Rel *start = rel;
    soinfo *lsi;

    for (size_t idx = 0; idx < count; ++idx, ++rel) {
        unsigned type = ELF32_R_TYPE(rel->r_info);
        unsigned sym = ELF32_R_SYM(rel->r_info);
        Elf32_Addr reloc = (Elf32_Addr) (rel->r_offset + si->load_bias);
        Elf32_Addr sym_addr = 0;
        char *sym_name = NULL;
        DL_ERR("Processing '%s' relocation at index %d", si->name, idx);
        if (type == 0) {
            continue;
        }
        if (sym != 0) {
            sym_name = (char *) (strtab + symtab[sym].st_name);
            s = soinfo_do_lookup(si, sym_name, &lsi, needed);
            DL_ERR("s value is 0x%x", s);
            if (s == NULL) {
                s = &symtab[sym];
                if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
                    DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name,
                           si->name);
                    return -1;
                }

            } else {
                sym_addr = (Elf32_Addr) (s->st_value + lsi->load_bias);
            }
            count_relocation(kRelocSymbol);
        } else {
            s = NULL;
        }

        switch (type) {
            case R_ARM_JUMP_SLOT:
                count_relocation(kRelocAbsolute);
                MARK(rel->r_offset);
                *((Elf32_Addr *) reloc) = sym_addr;
                break;
            case R_ARM_GLOB_DAT:
                count_relocation(kRelocAbsolute);
                MARK(rel->r_offset);
                *((Elf32_Addr *) reloc) = sym_addr;
                break;
            case R_ARM_ABS32:
                count_relocation(kRelocAbsolute);
                MARK(rel->r_offset);
                *((Elf32_Addr *) reloc) += sym_addr;
                break;
            case R_ARM_REL32:
                count_relocation(kRelocRelative);
                MARK(rel->r_offset);
                *((Elf32_Addr *) reloc) += sym_addr - rel->r_offset;
                break;
            case R_ARM_RELATIVE:
                count_relocation(kRelocRelative);
                MARK(rel->r_offset);
                if (sym) {
                    DL_ERR("odd RELATIVE form...");
                    return -1;
                }
                *((Elf32_Addr *) reloc) += si->base;
                break;
            case R_ARM_COPY:
                if ((si->flags & FLAG_EXE) == 0) {
                    DL_ERR("%s R_ARM_COPY relocations only supported for ET_EXEC", si->name);
                    return -1;
                }
                count_relocation(kRelocCopy);
                MARK(rel->r_offset);
                if (reloc == sym_addr) {
                    Elf32_Sym *src = soinfo_do_lookup(NULL, sym_name, &lsi, needed);

                    if (src == NULL) {
                        DL_ERR("%s R_ARM_COPY relocation source cannot be resolved", si->name);
                        return -1;
                    }
                    if (lsi->has_DT_SYMBOLIC) {
                        DL_ERR("%s invalid R_ARM_COPY relocation against DT_SYMBOLIC shared "
                                       "library %s (built with -Bsymbolic?)", si->name, lsi->name);
                        return -1;
                    }
                    if (s->st_size < src->st_size) {
                        DL_ERR("%s R_ARM_COPY relocation size mismatch (%d < %d)",
                               si->name, s->st_size, src->st_size);
                        return -1;
                    }
                    memcpy((void *) reloc, (void *) (src->st_value + lsi->load_bias), src->st_size);
                } else {
                    DL_ERR("%s R_ARM_COPY relocation target cannot be resolved", si->name);
                    return -1;
                }
                break;
            default:
                DL_ERR("unknown reloc type %d @ %p (%d)",
                       type, rel, (int) (rel - start));
                return -1;
        }
    }
    return 0;
}

static int reloc_library(soinfo *si, Elf32_Rel *rel, unsigned count) {
    unsigned i;
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    Elf32_Sym *s;

    for (i = 0; i < count; i++, rel++) {
        unsigned type = ELF32_R_TYPE(rel->r_info);
        unsigned reloc = (unsigned) (rel->r_offset + si->base);
        unsigned sym = ELF32_R_SYM(rel->r_info);
        unsigned sym_addr = 0;

        switch (type) {
            case R_ARM_JUMP_SLOT:
                *((unsigned *) reloc) = sym_addr;
                break;
            case R_ARM_GLOB_DAT:
                *((unsigned *) reloc) = sym_addr;
                break;
            case R_ARM_ABS32:
                *((unsigned *) reloc) += sym_addr;
                break;
            case R_ARM_REL32:
                *((unsigned *) reloc) += sym_addr - rel->r_offset;
                break;
            case R_ARM_RELATIVE:
                *((unsigned *) reloc) += si->base;
                break;
            case R_ARM_COPY:
                memcpy((void *) reloc, (void *) sym_addr, s->st_size);
                break;
            default:
                return -1;
        }
    }
    return 1;
}

static int
_phdr_table_set_load_prot(const Elf32_Phdr *phdr_table,
                          int phdr_count,
                          Elf32_Addr load_bias,
                          int extra_prot_flags) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0)
            continue;

        Elf32_Addr seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        Elf32_Addr seg_page_end = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        int ret = mprotect((void *) seg_page_start,
                           seg_page_end - seg_page_start,
                           PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

static int
_phdr_table_set_gnu_relro_prot(const Elf32_Phdr *phdr_table,
                               int phdr_count,
                               Elf32_Addr load_bias,
                               int prot_flags) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_GNU_RELRO)
            continue;
        Elf32_Addr seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        Elf32_Addr seg_page_end = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        int ret = mprotect((void *) seg_page_start,
                           seg_page_end - seg_page_start,
                           prot_flags);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

void
phdr_table_get_dynamic_section(const Elf32_Phdr *phdr_table,
                               int phdr_count,
                               Elf32_Addr load_bias,
                               Elf32_Dyn **dynamic,
                               size_t *dynamic_count,
                               Elf32_Word *dynamic_flags) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }
        *dynamic = (Elf32_Dyn *) (load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = (unsigned) (phdr->p_memsz / 8);
        }
        if (dynamic_flags) {
            *dynamic_flags = phdr->p_flags;
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}

int
phdr_table_get_arm_exidx(const Elf32_Phdr *phdr_table,
                         int phdr_count,
                         Elf32_Addr load_bias,
                         Elf32_Addr **arm_exidx,
                         unsigned *arm_exidx_count) {
    const Elf32_Phdr *phdr = phdr_table;
    const Elf32_Phdr *phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_ARM_EXIDX)
            continue;
        *arm_exidx = (Elf32_Addr *) (load_bias + phdr->p_vaddr);
        *arm_exidx_count = (unsigned) (phdr->p_memsz / 8);
        return 0;
    }
    *arm_exidx = NULL;
    *arm_exidx_count = 0;
    return -1;
}

static int soinfo_link_image(soinfo *si) {
    /* "base" might wrap around UINT32_MAX. */
    Elf32_Addr base = si->load_bias;//获取基地址
    const Elf32_Phdr *phdr = si->phdr;//获取 phrd地址
    int phnum = si->phnum;//获取 phnum的数量
    int relocating_linker = (si->flags & FLAG_LINKER) != 0;
    /* We can't debug anything until the linker is relocated */
    if (!relocating_linker) {
        DL_ERR("[ linking %s ]", si->name);
        DL_ERR("si->base = 0x%08x si->flags = 0x%08x", si->base, si->flags);
    }
    /* Extract dynamic section */ //定位动态节，通过动态节；抽取动态节
    size_t dynamic_count;
    Elf32_Word dynamic_flags;
    //这里的si就是dynamic，这里就是Elf32_Dyn _DYNAMIC[]
    phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,
                                   &dynamic_count, &dynamic_flags);
    if (si->dynamic == NULL) {
        if (!relocating_linker) {
            DL_ERR("missing PT_DYNAMIC in \"%s\"", si->name);
        }
        return 0;
    } else {
        if (!relocating_linker) {
            DL_ERR("dynamic = %p", si->dynamic);
        }
    }
    (void) phdr_table_get_arm_exidx(phdr, phnum, base,
                                    &si->ARM_exidx, (unsigned int *) &si->ARM_exidx_count);

    // Extract useful information from dynamic section. 从动态dynamic节区中抽取有用信息，储存在soinfo中
    uint32_t needed_count = 0;
    for (Elf32_Dyn *d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        DL_ERR("d = %p, d[0](tag) = 0x%08x d[1](val) = 0x%08x", d, d->d_tag, d->d_un.d_val);
        switch (d->d_tag) {
            case DT_HASH:
                si->nbucket = ((unsigned *) (base + d->d_un.d_ptr))[0];
                si->nchain = ((unsigned *) (base + d->d_un.d_ptr))[1];
                si->bucket = (unsigned *) (base + d->d_un.d_ptr + 8);
                si->chain = (unsigned *) (base + d->d_un.d_ptr + 8 + si->nbucket * 4);
                break;
            case DT_STRTAB:
                si->strtab = (const char *) (base + d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                si->symtab = (Elf32_Sym *) (base + d->d_un.d_ptr);
                break;
            case DT_PLTREL:
                if (d->d_un.d_val != DT_REL) {
                    DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
                    return 0;
                }
                break;
            case DT_JMPREL:
                si->plt_rel = (Elf32_Rel *) (base + d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si->plt_rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                break;
            case DT_REL:
                si->rel = (Elf32_Rel *) (base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si->rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si->plt_got = (unsigned *) (base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                break;
            case DT_RELA:
                DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
                return 0;
            case DT_INIT:
                si->init_func = (linker_function_t) (base + d->d_un.d_ptr);
                DL_ERR("%s constructors (DT_INIT) found at %p", si->name, si->init_func);
                break;
            case DT_FINI:
                si->fini_func = (linker_function_t) (base + d->d_un.d_ptr);
                DL_ERR("%s destructors (DT_FINI) found at %p", si->name, si->fini_func);
                break;
            case DT_INIT_ARRAY:
                si->init_array = (linker_function_t *) (base + d->d_un.d_ptr);
                DL_ERR("%s constructors (DT_INIT_ARRAY) found at %p", si->name, si->init_array);
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_FINI_ARRAY:
                si->fini_array = (linker_function_t *) (base + d->d_un.d_ptr);
                DL_ERR("%s destructors (DT_FINI_ARRAY) found at %p", si->name, si->fini_array);
                break;
            case DT_FINI_ARRAYSZ:
                si->fini_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_PREINIT_ARRAY:
                si->preinit_array = (linker_function_t *) (base + d->d_un.d_ptr);
                DL_ERR("%s constructors (DT_PREINIT_ARRAY) found at %p", si->name,
                       si->preinit_array);
                break;
            case DT_PREINIT_ARRAYSZ:
                si->preinit_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                break;
            case DT_TEXTREL:
                si->has_text_relocations = 1;
                break;
            case DT_SYMBOLIC:
                si->has_DT_SYMBOLIC = 1;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
                    si->has_text_relocations = 1;
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    si->has_DT_SYMBOLIC = 1;
                }
                break;
        }
    }

    DL_ERR("si->base = 0x%08x, si->strtab = %p, si->symtab = %p",
           si->base, si->strtab, si->symtab);

    // Sanity checks.再检查一遍，这种做法总是明确的
    if (relocating_linker && needed_count != 0) {
        DL_ERR("linker cannot have DT_NEEDED dependencies on other libraries");
        return 0;
    }
    if (si->nbucket == 0) {
        DL_ERR("empty/missing DT_HASH in \"%s\" (built with --hash-style=gnu?)", si->name);
        return 0;
    }
    if (si->strtab == 0) {
        DL_ERR("empty/missing DT_STRTAB in \"%s\"", si->name);
        return 0;
    }
    if (si->symtab == 0) {
        DL_ERR("empty/missing DT_SYMTAB in \"%s\"", si->name);
        return 0;
    }
    //分配一个soinfo*[]指针数组，用于存放本so库需要的外部so库的soinfo指针
    soinfo **needed = (soinfo **) alloca((1 + needed_count) * sizeof(soinfo *));
    soinfo **pneeded = needed;

    //依次获取dynamic数组中定义的每一个外部so库soinfo

    for (Elf32_Dyn *d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_NEEDED) {
            const char *library_name = si->strtab + d->d_un.d_val;
            DL_ERR("%s needs %s", si->name, library_name);
            soinfo *lsi = (soinfo *) dlopen(library_name, RTLD_NOW);
            if (lsi == NULL) {
                DL_ERR("could not load library \"%s\" needed by \"%s\";",
                       library_name, si->name);
                return 0;
            }
            *pneeded++ = lsi;
        }
    }
    *pneeded = NULL;

    if (si->has_text_relocations) {
        DL_ERR("%s has text relocations. This is wasting memory and is "
                       "a security risk. Please fix.", si->name);
        if (_phdr_table_set_load_prot(si->phdr, si->phnum, si->load_bias, PROT_WRITE) < 0) {
            DL_ERR("can't unprotect loadable segments for \"%s\": %s",
                   si->name, strerror(errno));
            return 0;
        }
    }
//    这里开始重定位，主要是去取 plt_rel和rel 段的值是否为NULL，如果不为空则去进行重定位操作
    if (si->plt_rel != NULL) {
        DL_ERR("[ relocating %s plt ]", si->name);
        if (soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed) == -1) {
            DL_ERR("[ relocating %s ]fail", si->name);
            return 0;
        }
    }
    if (si->rel != NULL) {
        if (soinfo_relocate(si, si->rel, si->rel_count, needed) == -1) {
            DL_ERR("[ relocating %s ] fail", si->name);
            return 0;
        }
    }
    si->flags |= FLAG_LINKED;//设置已链接标志
    DL_ERR("[ finished linking %s ]", si->name);

    if (si->has_text_relocations) {
        if (_phdr_table_set_load_prot(si->phdr, si->phnum, si->load_bias, 0) < 0) {
            DL_ERR("can't protect segments for \"%s\": %s",
                   si->name, strerror(errno));
            return 0;
        }
    }
    if (_phdr_table_set_gnu_relro_prot(si->phdr, si->phnum, si->load_bias, PROT_READ) < 0) {
        DL_ERR("can't enable GNU RELRO protection for \"%s\": %s",
               si->name, strerror(errno));
        return 0;
    }
    return 1;
}

static soinfo *soinfo_alloc(const char *name) {
    if (strlen(name) >= SOINFO_NAME_LEN) {
        DL_ERR("library name \"%s\" too long", name);
        return NULL;
    }
    // Initialize the new element.
    // 以下是我们修改后的代码, 我这里直接用了new ....嘿嘿.
    soinfo *si;
    memset(si, 0, sizeof(soinfo));
    strlcpy(si->name, name, sizeof(si->name));
    DL_ERR("name %s: allocated soinfo @ %p", name, si);
    return si;
}

void CallFunction(const char *function_name, linker_function_t function) {
    if (function == NULL || (uintptr_t) (function) == (uintptr_t) (-1)) {
        return;
    }

    DL_ERR("[ Calling %s @ %p for  ]", function_name, function);
    function();
    DL_ERR("[ Done calling %s @ %p for  ]", function_name, function);

}

void CallArray(const char *array_name, linker_function_t *functions, size_t count, int reverse) {
    if (functions == NULL) {
        return;
    }

    DL_ERR("[ Calling %s (size %d) @ %p for ]", array_name, count, functions);

    int begin = reverse ? (count - 1) : 0;
    int end = reverse ? (size_t) -1 : count;
    int step = reverse ? -1 : 1;

    for (int i = begin; i != end; i += step) {
        DL_ERR("[ %s[%d] == %p ]", array_name, i, functions[i]);
        CallFunction("function", functions[i]);
    }

    DL_ERR("[ Done calling %s for  ]", array_name);
}

void CallConstructors(soinfo *si) {

    CallArray("DT_INIT_ARRAY", si->init_array, si->init_array_count, 0);
}

static unsigned findSym(soinfo *si, const char *name) {
    unsigned i, hashval;
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    unsigned nbucket = (unsigned int) si->nbucket;
    unsigned *bucket = si->bucket;
    unsigned *chain = si->chain;

    hashval = elfhash(name);
    for (i = bucket[hashval % nbucket]; i != 0; i = chain[i]) {
        if (symtab[i].st_shndx != 0) {
            if (strcmp(strtab + symtab[i].st_name, name) == 0) {
                return symtab[i].st_value;
            }
        }
    }
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    jint (*real_JNI_OnLoad)(JavaVM *, void *);
    handler = dlopen("libnative-lib.so", RTLD_NOW);
    Elf32_Ehdr *ehdr_shell;
    Elf32_Phdr *phdr_main;
    Elf32_Addr min_vaddr;
    Elf32_Addr max_vaddr;
    unsigned long base;
    base = getLibAddr();
    ehdr_shell = (Elf32_Ehdr *) base;
    Elf32_Addr mian_elf_off = ehdr_shell->e_shoff;
    ehdr_main = (Elf32_Ehdr *) (mian_elf_off + base);//+base
    if (checkMagicNum(ehdr_main) == -1) {
        DL_ERR("Not ELF");
        return JNI_VERSION_1_6;
    }
    Elf32_Off main_phrd_off = ehdr_main->e_phoff;
    phdr_main = (Elf32_Phdr *) (main_phrd_off + (unsigned) ehdr_main);//偏移量
    phdr_num = ehdr_main->e_phnum;
    phdr_table = phdr_main;

    size_t load_size = phdr_table_get_load_size(phdr_main, phdr_num, &min_vaddr,
                                                &max_vaddr);
    uint8_t *addr = (uint8_t *) (min_vaddr);
    if (load_size == 0) {
        return JNI_VERSION_1_6;
    }
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    //mmap函数的参数注意 第一个为mmap的起始地址，第二个为mmap的大小，最后一个被mmap的起始地址
    void *start = mmap((void *) addr, load_size, PROT_NONE, mmap_flags, -1, 0);//mmap进内存
    if (start == MAP_FAILED) {
        DL_ERR("couldn't reserve %d bytes of address space for \"%s\"", load_size);
        return JNI_VERSION_1_6;
    }
    load_start = start;
    load_bias = (Elf32_Addr) ((uint8_t *) (start) - addr);//load_biad_的值是什么？为什么要减去addr
    if (LoadSegments(load_bias) == 0) {
        DL_ERR("load_sgement fail\n");
    }
    FindPhdr();
    soinfo *main_si = soinfo_alloc("loader");
    if (main_si == NULL) {
        return JNI_VERSION_1_6;
    }
    main_si->dynamic = NULL;
    main_si->flags = 0;
    main_si->entry = 0;
    main_si->size = (unsigned int) load_size;
    main_si->phnum = phdr_num;
    main_si->load_bias = (Elf32_Addr) load_start;
    main_si->base = load_bias;
    main_si->phdr = loaded_phdr;
    if (!soinfo_link_image(main_si)) {
        DL_ERR("soinfo_link_image fail");
    }
    linker_function_t *init_function = main_si->init_array;
    size_t init_size = main_si->init_array_count;
    real_JNI_OnLoad = (jint (*)(JavaVM *, void *)) (main_si->base + findSym(main_si, "JNI_OnLoad"));
    if (real_JNI_OnLoad == NULL) {
        DL_ERR("cannot find sym %s\n", "JNI_OnLoad");
    }
    Elf32_Addr SoinfoAdd = PAGE_START((Elf32_Addr) handler);
    mprotect((void *) (const void *) SoinfoAdd, sizeof(soinfo) + (Elf32_Addr) handler - SoinfoAdd,
             PROT_READ | PROT_WRITE);
    handler->load_bias = main_si->load_bias;
    handler->size = main_si->size;
    handler->base = main_si->base;
    handler->ARM_exidx_count = main_si->ARM_exidx_count;
    handler->ARM_exidx = main_si->ARM_exidx;
    handler->strtab = main_si->strtab;
    handler->symtab = main_si->symtab;
    handler->nbucket = main_si->nbucket;
    handler->bucket = main_si->bucket;
    handler->nchain = main_si->nchain;
    handler->chain = main_si->chain;
    CallArray("DT_INIT_ARRAY", init_function, init_size, 0);
    jint JNI_VERSION = real_JNI_OnLoad(vm, reserved);
    return JNI_VERSION;
}