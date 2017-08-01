#include "woody.h"

Elf64_Shdr *get_section_header_by_name(void *data, char *name)
{
    Elf64_Ehdr *elf_header = data;
    Elf64_Shdr *section_header = data + elf_header->e_shoff;
    Elf64_Half shnum = elf_header->e_shnum;
    Elf64_Half i;

    for (i = 0; i < shnum; ++i)
    {
        if (!strcmp((data + (&((Elf64_Shdr *)(data + elf_header->e_shoff))[elf_header->e_shstrndx])->sh_offset) + section_header[i].sh_name, name))
            return &section_header[i];
    }
    return 0;
}

Elf64_Shdr *get_section_header_by_type(void *data, Elf64_Word type)
{
    Elf64_Ehdr *elf_header = data;
    Elf64_Shdr *section_header = data + elf_header->e_shoff;
    Elf64_Half shnum = elf_header->e_shnum;
    Elf64_Half i;

    for (i = 0; i < shnum; ++i)
    {
        if (section_header[i].sh_type == type)
            return &section_header[i];
    }
    return 0;
}
