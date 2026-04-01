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

	bait_elf_free(&elf);
	return 0;
}