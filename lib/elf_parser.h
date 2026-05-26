#ifndef BAIT_ELF_PARSER_H
#define BAIT_ELF_PARSER_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t    *base;           // mmap base pointer
    size_t      size;           // file size
    Elf64_Ehdr *ehdr;           // ELF header (points into base)
    Elf64_Shdr *shdrs;          // section header array
    Elf64_Phdr *phdrs;          // program header array
    const char *shstrtab;       // section name string table
    Elf64_Dyn  *dynamic;
    size_t      dynamic_count;
    int         has_bind_now;
    uint64_t    dt_flags;
    uint64_t    dt_strtab_va;
    uint64_t    dt_symtab_va;
} bait_elf_t;

typedef struct bait_checksec_t {
    char*      Arch[16];
    uint8_t    PIE;
    uint8_t    NX;
    uint8_t    RELRO;
    uint8_t    stack;
    uint8_t    stripped;
} bait_checksec_t;

bait_checksec_t bait_elf_checksec(bait_elf_t *elf);

int bait_elf_parse_dynamic(bait_elf_t *elf);

int  bait_elf_load(const char *path, bait_elf_t *elf);
void bait_elf_free(bait_elf_t *elf);

Elf64_Shdr *bait_elf_find_section(bait_elf_t *elf, const char *name);
void        bait_elf_print_sections(bait_elf_t *elf);

Elf64_Phdr *bait_elf_find_segment(bait_elf_t *elf, uint32_t type);
void        bait_elf_print_segments(bait_elf_t *elf);

int64_t bait_elf_va_to_offset(bait_elf_t *elf, Elf64_Addr vaddr);


#endif