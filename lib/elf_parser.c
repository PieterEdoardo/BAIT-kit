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

int bait_elf_parse_dynamic(bait_elf_t *elf) {
    Elf64_Phdr* phdr = bait_elf_find_segment(elf, PT_DYNAMIC);
    if (phdr == NULL) {
        return -1;
    }

    Elf64_Dyn* dyn = (Elf64_Dyn*)(elf->base + phdr->p_offset);

    elf->dynamic = dyn;

    while (dyn->d_tag != DT_NULL) {
        switch (dyn->d_tag) {
            case DT_BIND_NOW:
                elf->has_bind_now = 1;
                break;
            case DT_FLAGS:
                elf->dt_flags = dyn->d_un.d_val;
                break;
            case DT_STRTAB:
                elf->dt_strtab_va = dyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                elf->dt_symtab_va = dyn->d_un.d_ptr;
                break;
            default:
                break;
        }
        elf->dynamic_count++;
        dyn++;
    }
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

static const char *phdr_type_str(uint32_t type) {
    switch (type) {
        case PT_NULL:         return "NULL";
        case PT_LOAD:         return "LOAD";
        case PT_DYNAMIC:      return "DYNAMIC";
        case PT_INTERP:       return "INTERP";
        case PT_NOTE:         return "NOTE";
        case PT_SHLIB:        return "SHLIB";
        case PT_PHDR:         return "PHDR";
        case PT_TLS:          return "TLS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK:    return "GNU_STACK";
        case PT_GNU_RELRO:    return "GNU_RELRO";
        default:              return "UNKNOWN";
    }
}

void bait_elf_print_segments(bait_elf_t *elf) {
    printf("%-16s %-10s %-18s %-18s %-10s %-10s %-6s\n",
       "Type", "Flags", "File offset", "Virt addr",
       "File size", "Mem size", "Align");

    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        Elf64_Phdr *p = &elf->phdrs[i];

        // decode flags into RWX string
        char flags[4] = "---";
        if (p->p_flags & PF_R) flags[0] = 'R';
        if (p->p_flags & PF_W) flags[0] = 'W';
        if (p->p_flags & PF_X) flags[0] = 'X';

        printf("%-16s %-10s 0x%-16lx 0x%-16lx 0x%-8lx 0x%-8lx 0x%lx\n",
           phdr_type_str(p->p_type),
           flags,
           p->p_offset,
           p->p_vaddr,
           p->p_filesz,
           p->p_memsz,
           p->p_align
        );

        // for INTERP, print the interpreter path directly
        // it's a null-terminated string sitting at p_offset in the file
        if (p->p_type == PT_INTERP) {
            printf("[Requesting program interpreter: %s]\n",
                   (char *)(elf->base + p->p_offset));
        }
    }
}

Elf64_Phdr *bait_elf_find_segment(bait_elf_t *elf, uint32_t type) {
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        if (elf->phdrs[i].p_type == type) {
            return &elf->phdrs[i];
        }
    }

    return NULL;
}

int64_t bait_elf_va_to_offset(bait_elf_t *elf, uint64_t vaddr) {
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        Elf64_Phdr *p = &elf->phdrs[i];

        if (p->p_type != PT_LOAD)
            continue;

        // check VA falls within the file-backed portion of this segment
        // deliberately use p_filesz not p_memsz — .bss has no file backing
        if (vaddr >= p->p_vaddr && vaddr < p->p_vaddr + p->p_filesz)
            return (int64_t)(p->p_vaddr + (vaddr -p->p_vaddr));
    }

    return -1;  // no PT_LOAD segment owns this VA
}

bait_checksec_t bait_elf_checksec(bait_elf_t* elf) {
    bait_checksec_t checksec = {0};

    // PIE
    if (elf->ehdr->e_type == ET_DYN) {
        checksec.PIE = 1;
    } else if (elf->ehdr->e_type == ET_EXEC) {
        checksec.PIE = 0;
    }

    // NX
    Elf64_Phdr* stack = bait_elf_find_segment(elf, PT_GNU_STACK);
    if (stack != NULL) checksec.NX = !(stack->p_flags & PF_X);

    // RELRO
    Elf64_Phdr* relro = bait_elf_find_segment(elf, PT_GNU_RELRO);
    if (relro == NULL) {
        checksec.RELRO = 0;
    } else if (elf->has_bind_now || elf->dt_flags & DF_BIND_NOW) {
        checksec.RELRO = 2;
    } else {
        checksec.RELRO = 1;
    }

    // Stack Canary
    // bait_elf_find_section(elf, ".dynsym")
    checksec.stack = 0;

    if (!bait_elf_find_section(elf, ".symtab")) {
        checksec.stripped = 1;
    } else {
        checksec.stripped = 0;
    }

    return checksec;
}