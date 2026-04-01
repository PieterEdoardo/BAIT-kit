#ifndef BAIT_ELF_PARSER_H
#define BAIT_ELF_PARSER_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t    *base;       // mmap base pointer
    size_t      size;       // file size
    Elf64_Ehdr *ehdr;       // ELF header (points into base)
    Elf64_Shdr *shdrs;      // section header array
    Elf64_Phdr *phdrs;      // program header array
    const char *shstrtab;   // section name string table
} bait_elf_t;

int  bait_elf_load(const char *path, bait_elf_t *elf);
void bait_elf_free(bait_elf_t *elf);

Elf64_Shdr *bait_elf_find_section(bait_elf_t *elf, const char *name);
void        bait_elf_print_sections(bait_elf_t *elf);

#endif