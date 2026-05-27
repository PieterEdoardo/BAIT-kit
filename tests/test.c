#include <elf.h>
#include <stdio.h>
#include "elf_parser.h"

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s <elf-binary>\n", argv[0]);
		return 1;
	}

	bait_elf_t elf = {0};

	if (bait_elf_load(argv[1], &elf) < 0) {
		fprintf(stderr, "failed to load ELF: %s\n", argv[1]);
		return 1;
	}

	printf("=== ELF Header ===\n");
	printf("Entry point:     0x%lx\n", elf.ehdr->e_entry);
	printf("Section count:   %d\n",    elf.ehdr->e_shnum);
	printf("Program headers: %d\n",    elf.ehdr->e_phnum);
	printf("Type:            %d\n",    elf.ehdr->e_type);  // 2=ET_EXEC, 3=ET_DYN

	printf("\n=== Sections ===\n");
	bait_elf_print_sections(&elf);

	printf("\n=== Section lookup ===\n");
	Elf64_Shdr *text = bait_elf_find_section(&elf, ".text");
	if (text)
		printf(".text found — offset: 0x%lx  size: 0x%lx\n",
			   text->sh_offset, text->sh_size);
	else
		printf(".text not found (stripped?)\n");
	printf("\n=== Segments ===\n");
	printf("DEBUG e_phnum: %d\n", elf.ehdr->e_phnum);

	bait_elf_print_segments(&elf);
	// test the translator using .text's virtual address
	// .text sh_addr is its VA, we should get back sh_offset
	if (text) {
		int64_t off = bait_elf_va_to_offset(&elf, text->sh_addr);
		printf("\n=== VA→offset check ===\n");
		printf(".text VA:            0x%lx\n", text->sh_addr);
		printf(".text file offset:   0x%lx\n", text->sh_offset);
		printf("translated offset:   0x%lx\n", off);
		printf("match: %s\n", off == (int64_t)text->sh_offset ? "YES" : "NO");
	}

	printf("\n=== Dynamic ===\n");
	if (bait_elf_parse_dynamic(&elf) == 0) {
		printf("dynamic entries: %zu\n", elf.dynamic_count);
		printf("has_bind_now:    %d\n",  elf.has_bind_now);
		printf("dt_flags:        0x%lx\n", elf.dt_flags);
		printf("dt_strtab_va:    0x%lx\n", elf.dt_strtab_va);
		printf("dt_symtab_va:    0x%lx\n", elf.dt_symtab_va);
	} else {
		printf("no .dynamic section (statically linked?)\n");
	}

	printf("\n=== Checksec ===\n");
	bait_checksec_t checksec = bait_elf_checksec(&elf);
	printf("PIE:        %s\n", checksec.PIE ? "PIE" : "No PIE");
	printf("NX:         %s\n", checksec.NX ? "NX enabled" : "NX disabled");
	if (checksec.RELRO == 0) {
		printf("RELRO:      %s\n", "None");
	} else if (checksec.RELRO == 1) {
		printf("RELRO:      %s\n", "Partial");
	} else if (checksec.RELRO == 2) {
		printf("RELRO:      %s\n", "Full");
	}
	printf("Stack:      %s\n", "Not Implemented");
	printf("Stripped:	%s\n", checksec.stripped ? "Stripped binary" : "Not stripped binary");



	bait_elf_free(&elf);
	return 0;
}