#include "woody.h"

Elf64_Phdr *get_loadable_segment(Elf64_Phdr *program_header, Elf64_Half phnum, Elf64_Word type, Elf64_Word flags)
{
    Elf64_Half i;

    for (i = 0; i < phnum; ++i)
    {
        if (program_header[i].p_type == type && ((program_header[i].p_flags & flags) == flags))
            return &program_header[i];
    }
    return 0;
}
