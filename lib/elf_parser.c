#include "elf_parser.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int validate_elf(bait_elf_t *elf) {
    if (elf->size < sizeof(Elf64_Ehdr))
        return -1;

    uint8_t *mag = elf->ehdr->e_ident;
    if (mag[EI_MAG0] != ELFMAG0 || mag[EI_MAG1] != ELFMAG1 ||
        mag[EI_MAG2] != ELFMAG2 || mag[EI_MAG3] != ELFMAG3)
        return -1;

    if (mag[EI_CLASS] != ELFCLASS64)   // 64-bit only for now
        return -1;

    if (mag[EI_DATA] != ELFDATA2LSB)   // little-endian only for now
        return -1;

    return 0;
}

int bait_elf_load(const char *path, bait_elf_t *elf) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    elf->size = st.st_size;
    elf->base = mmap(NULL, elf->size, PROT_WRITE | PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (elf->base == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    elf->ehdr = (Elf64_Ehdr *)elf->base;

    if (validate_elf(elf) < 0) {
        fprintf(stderr, "validate_elf failed — not a valid ELF64 LE binary\n");
        bait_elf_free(elf);
        return -1;
    }

    elf->shdrs    = (Elf64_Shdr *)(elf->base + elf->ehdr->e_shoff);
    elf->phdrs    = (Elf64_Phdr *)(elf->base + elf->ehdr->e_phoff);
    elf->shstrtab = (const char *)(elf->base +
                    elf->shdrs[elf->ehdr->e_shstrndx].sh_offset);

    return 0;
}

void bait_elf_free(bait_elf_t *elf) {
    if (elf->base && elf->base != MAP_FAILED)
        munmap(elf->base, elf->size);
    memset(elf, 0, sizeof(*elf));
}

Elf64_Shdr *bait_elf_find_section(bait_elf_t *elf, const char *name) {
    for (int i = 0; i < elf->ehdr->e_shnum; i++) {
        const char *sname = elf->shstrtab + elf->shdrs[i].sh_name;
        if (strcmp(sname, name) == 0)
            return &elf->shdrs[i];
    }
    return NULL;
}

void bait_elf_print_sections(bait_elf_t *elf) {
    printf("%-4s %-20s %-10s %-10s %-10s\n",
           "Idx", "Name", "Type", "Offset", "Size");
    for (int i = 0; i < elf->ehdr->e_shnum; i++) {
        Elf64_Shdr *s = &elf->shdrs[i];
        printf("%-4d %-20s 0x%-8x 0x%-8lx 0x%-8lx\n",
               i,
               elf->shstrtab + s->sh_name,
               s->sh_type,
               s->sh_offset,
               s->sh_size);
    }
}