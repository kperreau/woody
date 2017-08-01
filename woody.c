#include "woody.h"

#define SHELLCODE_MAX_SIZE 1024

char print_woody_64[] = ""
"\x48\x8d\x35\xf9\xff\xff\xff"                             // lea    rsi,[rip+0xfffffffffffffff9]
"\x48\x83\xc6\x21"                                         // add    rsi,0x21
"\xbf\x01\x00\x00\x00"                                     // mov    edi,0x1
"\xba\x0e\x00\x00\x00"                                     // mov    edx,0xe
"\xb8\x01\x00\x00\x00"                                     // mov    eax,0x1
"\x0f\x05"                                                 // syscall
"\xe9\x0e\x00\x00\x00"                                     // jmp    --------------
"\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a" // "....WOODY....\n"    |
"";                                                        // <--------------------

char depack_64[] = ""
"\x59"                                                     // pop    rcx
"\x5a"                                                     // pop    rdx
"\x48\x8d\x05\xf9\xff\xff\xff"                             // lea    rax,[rip+0xfffffffffffffff9]
"\x48\x01\xc2"                                             // add    rdx,rax
"\xfe\x02"                                                 // inc    BYTE PTR [rdx] <--
"\x48\xff\xc2"                                             // inc    rdx               |
"\x48\xff\xc9"                                             // dec    rcx               |
"\x75\xf6"                                                 // jne    ------------------
"";

char decrypt_64[] = ""
// <start>:
"\xeb\x10"                      // jmp    12 <_skip_key>
// <_key>:
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// <_skip_key>:
"\x4c\x8d\x0d\xe9\xff\xff\xff"  // lea    r9,[rip+0xffffffffffffffe9]        # 2 <_key>
"\x41\x5a"                      // pop    r10
"\x41\x58"                      // pop    r8
"\x4c\x8d\x25\xc9\xff\xff\xff"  // lea    r12,[rip+0xffffffffffffffc9]        # ffffffffffffffed <end+0xfffffffffffffe8c>
"\x4d\x01\xe0"                  // add    r8,r12
"\x49\x89\xe4"                  // mov    r12,rsp
"\x49\x83\xec\x10"              // sub    r12,0x10
"\xe8\x0a\x00\x00\x00"          // call   3d <key_expand>
"\xe8\xd2\x00\x00\x00"          // call   10a <decrypt>
"\xe9\x24\x01\x00\x00"          // jmp    161 <end>
// <key_expand>:
"\xf3\x41\x0f\x6f\x01"          // movdqu xmm0,XMMWORD PTR [r9]
"\x0f\x28\xe8"                  // movaps xmm5,xmm0
"\x66\x0f\xef\xd2"              // pxor   xmm2,xmm2
"\x66\x0f\x3a\xdf\xc8\x01"      // aeskeygenassist xmm1,xmm0,0x1
"\xe8\x9c\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x0f\x38\xdb\xf0"          // aesimc xmm6,xmm0
"\x66\x0f\x3a\xdf\xc8\x02"      // aeskeygenassist xmm1,xmm0,0x2
"\xe8\x8c\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x0f\x38\xdb\xf8"          // aesimc xmm7,xmm0
"\x66\x0f\x3a\xdf\xc8\x04"      // aeskeygenassist xmm1,xmm0,0x4
"\xe8\x7c\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xc0"      // aesimc xmm8,xmm0
"\x66\x0f\x3a\xdf\xc8\x08"      // aeskeygenassist xmm1,xmm0,0x8
"\xe8\x6b\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xc8"      // aesimc xmm9,xmm0
"\x66\x0f\x3a\xdf\xc8\x10"      // aeskeygenassist xmm1,xmm0,0x10
"\xe8\x5a\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xd0"      // aesimc xmm10,xmm0
"\x66\x0f\x3a\xdf\xc8\x20"      // aeskeygenassist xmm1,xmm0,0x20
"\xe8\x49\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xd8"      // aesimc xmm11,xmm0
"\x66\x0f\x3a\xdf\xc8\x40"      // aeskeygenassist xmm1,xmm0,0x40
"\xe8\x38\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xe0"      // aesimc xmm12,xmm0
"\x66\x0f\x3a\xdf\xc8\x80"      // aeskeygenassist xmm1,xmm0,0x80
"\xe8\x27\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xe8"      // aesimc xmm13,xmm0
"\x66\x0f\x3a\xdf\xc8\x1b"      // aeskeygenassist xmm1,xmm0,0x1b
"\xe8\x16\x00\x00\x00"          // call   f0 <key_expansion>
"\x66\x44\x0f\x38\xdb\xf0"      // aesimc xmm14,xmm0
"\x66\x0f\x3a\xdf\xc8\x36"      // aeskeygenassist xmm1,xmm0,0x36
"\xe8\x05\x00\x00\x00"          // call   f0 <key_expansion>
"\x44\x0f\x28\xf8"              // movaps xmm15,xmm0
"\xc3"                          // ret
// <key_expansion>:
"\x66\x0f\x70\xc9\xff"          // pshufd xmm1,xmm1,0xff
"\x0f\xc6\xd0\x10"              // shufps xmm2,xmm0,0x10
"\x66\x0f\xef\xc2"              // pxor   xmm0,xmm2
"\x0f\xc6\xd0\x8c"              // shufps xmm2,xmm0,0x8c
"\x66\x0f\xef\xc2"              // pxor   xmm0,xmm2
"\x66\x0f\xef\xc1"              // pxor   xmm0,xmm1
"\xc3"                          // ret
// <decrypt>:
"\x49\x83\xfa\x10"              // cmp    r10,0x10
"\x7c\x50"                      // jl     160 <done>
"\x41\x0f\x10\x00"              // movups xmm0,XMMWORD PTR [r8]
"\x66\x41\x0f\xef\xc7"          // pxor   xmm0,xmm15
"\x66\x41\x0f\x38\xde\xc6"      // aesdec xmm0,xmm14
"\x66\x41\x0f\x38\xde\xc5"      // aesdec xmm0,xmm13
"\x66\x41\x0f\x38\xde\xc4"      // aesdec xmm0,xmm12
"\x66\x41\x0f\x38\xde\xc3"      // aesdec xmm0,xmm11
"\x66\x41\x0f\x38\xde\xc2"      // aesdec xmm0,xmm10
"\x66\x41\x0f\x38\xde\xc1"      // aesdec xmm0,xmm9
"\x66\x41\x0f\x38\xde\xc0"      // aesdec xmm0,xmm8
"\x66\x0f\x38\xde\xc7"          // aesdec xmm0,xmm7
"\x66\x0f\x38\xde\xc6"          // aesdec xmm0,xmm6
"\x66\x0f\x38\xdf\xc5"          // aesdeclast xmm0,xmm5
"\x41\x0f\x11\x00"              // movups XMMWORD PTR [r8],xmm0
"\x49\x83\xea\x10"              // sub    r10,0x10
"\x49\x83\xc0\x10"              // add    r8,0x10
"\xeb\xaa"                      // jmp    10a <decrypt>
// <done>:
"\xc3"                          // ret
"";

#define LOADER_WRITE(code, len) { memcpy(loader + loader_len, code, len) ; loader_len += len ; }
#define LOADER_PUSH(val)        { loader[loader_len++] = '\x68'          ; tmp = (val)       ; memcpy(loader + loader_len, &tmp, 4) ; loader_len += 4 ;  }
#define LOADER_JUMP(val)        { loader[loader_len++] = '\xe9'          ; tmp = ((val) - 4) ; memcpy(loader + loader_len, &tmp, 4) ; loader_len += 4 ;  }

static int write_loader(char *entry, Elf64_Addr loader_vaddr, Elf64_Addr old_entry, Elf64_Addr text_vstart, Elf64_Off text_len, char *key)
{
    char loader[SHELLCODE_MAX_SIZE] = {0};
    size_t loader_len = 0;
    Elf64_Addr tmp;
    uint32_t i;

    LOADER_WRITE("\x50\x57\x56\x54\x52\x51", 6);                  // push all
    LOADER_WRITE("\x9c", 1);                                      // pushfq

    LOADER_WRITE(print_woody_64, sizeof(print_woody_64) - 1);     // print_woody

    LOADER_PUSH(text_vstart - (loader_vaddr + loader_len) + 0xa); // calcul pour avoir l'offset (auquel on ajoutera rip)
    LOADER_PUSH(text_len);
    memcpy(decrypt_64 + 2, key, 16);
    LOADER_WRITE(decrypt_64, sizeof(decrypt_64) - 1);               // depack

    LOADER_WRITE("\x9d", 1);                                      // popfq
    LOADER_WRITE("\x59\x5a\x5c\x5e\x5f\x58", 6);                  // pop all

    LOADER_JUMP(old_entry - (loader_vaddr + loader_len));         // jump relatif

    memcpy(entry, loader, SHELLCODE_MAX_SIZE); // copy loader
    printf("[+] assembled loader code (%lu bytes)\n", loader_len);
    return loader_len;
}

static void pack(char *start, Elf64_Off len, char *key)
{
    /* size_t zlen; */
    /* LZSS(start, len, &zlen); // compress */
    /* printf("[+] compressed at %lu%%\n", zlen * 100 / len); */
	char **_key = &key;

	__asm__ __volatile__(
            "call get_key;" // key dans xmm0
			"call key_expand;"
            "call encrypt;"
			"xor rax, rax;"
			"jmp end;"

        "get_key:"
			"movups xmm0, [%1];"
            "ret;"

		"key_expand:"
			"movaps xmm5, xmm0;"
			"pxor xmm2, xmm2;"

			"aeskeygenassist xmm1, xmm0, 0x1;"
			"call key_expansion;"
			"movaps xmm6, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x2;"
			"call key_expansion;"
			"movaps xmm7, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x4;"
			"call key_expansion;"
			"movaps xmm8, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x8;"
			"call key_expansion;"
			"movaps xmm9, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x10;"
			"call key_expansion;"
			"movaps xmm10, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x20;"
			"call key_expansion;"
			"movaps xmm11, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x40;"
			"call key_expansion;"
			"movaps xmm12, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x80;"
			"call key_expansion;"
			"movaps xmm13, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x1b;"
			"call key_expansion;"
			"movaps xmm14, xmm0;"
			"aeskeygenassist xmm1, xmm0, 0x36;"
			"call key_expansion;"
			"movaps xmm15, xmm0;"
			"ret;"

		"key_expansion:"
			"pshufd xmm1, xmm1, 0b11111111;"
			"shufps xmm2, xmm0, 0b00010000;"
			"pxor xmm0, xmm2;"
			"shufps xmm2, xmm0, 0b10001100;"
			"pxor xmm0, xmm2;"
			"pxor xmm0, xmm1;"
			"ret;"

		"encrypt:"
			"cmp %3, 0x10;"
			"jl done;"
			"mov rax, %2;"
			"movaps xmm0, [rax];"
			"pxor xmm0, xmm5;"
			"aesenc xmm0, xmm6;"
			"aesenc xmm0, xmm7;"
			"aesenc xmm0, xmm8;"
			"aesenc xmm0, xmm9;"
			"aesenc xmm0, xmm10;"
			"aesenc xmm0, xmm11;"
			"aesenc xmm0, xmm12;"
			"aesenc xmm0, xmm13;"
			"aesenc xmm0, xmm14;"
			"aesenclast xmm0, xmm15;"
			"mov rax, %0;"
            "movaps [rax], xmm0;"
            "sub %3, 0x10;"
			"add %0, 0x10;"
            "jmp encrypt;"
            "done:"
		"ret;"

		"end:"
		: "=&m" (start)
		: "R" (*_key), "m" (start), "r" (len)
		: "rax"
	);
}

static int already_packed(void *data)
{
    Elf64_Ehdr *elf_header = data;
    Elf64_Shdr *section_header = data + elf_header->e_shoff;
    Elf64_Half shnum = elf_header->e_shnum;
    Elf64_Half i;

    for (i = 0; i < shnum; ++i)
    {
        if (!strcmp((data + (&((Elf64_Shdr *)(data + elf_header->e_shoff))[elf_header->e_shstrndx])->sh_offset) + section_header[i].sh_name, "") && section_header[i].sh_type != PT_NULL)
        {
            printf("[!] already packed !\n");
            return 1;
        }
    }
    return 0;
}

static void generate_key(char *key, char *user_key)
{
    uint32_t i;
    int fd_ur;

    if (user_key && strnlen(user_key, 16) == 16)
    {
        printf("[+] using user key (%16s)\n", user_key);
        memcpy(key, user_key, 16);
    }
    else
    {
        printf("[+] generating random key\n");
        fd_ur = open("/dev/urandom", O_RDONLY);
        if (fd_ur == -1)
            return ;

        if (read(fd_ur, key, 16) < 16)
            return ;
    }
    printf("[+] key: ");
    for (i = 0; i < 16; ++i)
        printf("%02hhx", key[i]);
    printf("\n");
}

#ifdef DEBUG

#define WRITE_FILE(src, len, name) {\
    /* printf("[w] %-20s %#-8lx %#8lx\n", (name), (unsigned long)(src), (len));\ */
    memcpy(cur, (src), (len));\
    cur += len;\
}

#define WRITE_FILE_ZEROES(len, name) {\
    char *__tmp = calloc(len, 1);\
    /* printf("[w] %-20s    zeros %#8lx\n", (name), (len));\ */
    memcpy(cur, __tmp, (len));\
    cur += (len);\
    free(__tmp);\
}

#else

#define WRITE_FILE(src, len, name) {\
    memcpy(cur, (src), (len));\
    cur += len;\
}

#define WRITE_FILE_ZEROES(len, name) {\
    char *__tmp = calloc(len, 1);\
    memcpy(cur, __tmp, (len));\
    cur += (len);\
    free(__tmp);\
}

#endif


static int start(char *fn, char *user_key)
{
    Elf64_Ehdr *ehdr;                      // ehdr de fn
    Elf64_Ehdr *out_ehdr;                  // ehdr de woody
    Elf64_Phdr *phdr;                      // phdr de fn
    Elf64_Shdr *shdr;                      // shdr de fn;
    Elf64_Shdr new_shdr;                   // shdr avec section en rab

    void       *data;                      // fichier dentree
    void       *out;                       // fichier de sortie
    void       *cur;                       // curseur de out
    size_t     size;                       // taille du fichier de sortie
    size_t     old_size;                   // taille du fichier dentree

    Elf64_Phdr *data_phdr;                 // DATA de fn
    Elf64_Phdr *out_data_phdr;             // DATA de woody
    Elf64_Phdr *text_phdr;                 // TEXT de fn
    Elf64_Phdr *out_text_phdr;             // TEXT de woody

    size_t     bss_len;                    // taille du bss
    size_t     cave_len;                   // ecart entre fin de TEXT et debut de LOAD
    char       loader[SHELLCODE_MAX_SIZE]; // mem pour le loader
    size_t     loader_len;                 // taille reele du loader
    void       *text_start;                // debut du code
    Elf64_Addr old_entry;                  // ancien e_entry
    Elf64_Addr text_vstart;                // vaddr du code
    Elf64_Off  text_len;                   // taille du texte a (de)packer
    Elf64_Addr loader_vstart;              // vaddr du loader
    char       key[16];                    // <-- key a rendre dynamique

    data = read_file(fn, &size);
    if (!data)
        goto err;
    ehdr = data;
    if (memcmp(ehdr->e_ident, "\x7f\x45\x4c\x46\x02", 5)) { printf("[!] not an elf64 file\n"); goto err;  }
    printf("[*] opened %s (%#lx bytes)\n", fn, size);
	if (already_packed(data))
        goto err_free_data;
    phdr = data + ehdr->e_phoff;
    (void)phdr;
    shdr = data + ehdr->e_shoff;
    text_phdr = get_loadable_segment(data + ehdr->e_phoff, ehdr->e_phnum, PT_LOAD, PF_R | PF_X);
    if (!text_phdr) { printf("[-] no text segment\n"); goto err_free_data; }
    data_phdr = get_loadable_segment(data + ehdr->e_phoff, ehdr->e_phnum, PT_LOAD, PF_R | PF_W);
    if (!data_phdr) { printf("[-] no data segment\n"); goto err_free_data; }
    printf("[*] elf header found\n");

    bss_len = data_phdr->p_memsz - data_phdr->p_filesz;
    cave_len = data_phdr->p_offset - text_phdr->p_filesz;

    // on cree la copie du fichier avec de la place pour le loader, la section bss, et le section header en rab
    old_size = size;
    size += SHELLCODE_MAX_SIZE + bss_len + sizeof(Elf64_Shdr);
    out = malloc(size);
    cur = out;
    memcpy(out, data, old_size);

    out_ehdr = out;

    old_entry = ehdr->e_entry;

    WRITE_FILE(data + text_phdr->p_offset, text_phdr->p_filesz, "text");

    WRITE_FILE_ZEROES(cave_len, "cave");

    WRITE_FILE(data + data_phdr->p_offset, data_phdr->p_filesz, "data");

    // on agrandit DATA qu'il prenne le loader et bss, et on passe DATA et TEXT en RWX
    out_text_phdr = get_loadable_segment(out + out_ehdr->e_phoff, out_ehdr->e_phnum, PT_LOAD, PF_R | PF_X);
    out_data_phdr = get_loadable_segment(out + out_ehdr->e_phoff, out_ehdr->e_phnum, PT_LOAD, PF_R | PF_W);
    out_data_phdr->p_filesz += SHELLCODE_MAX_SIZE + bss_len;
    out_data_phdr->p_memsz += SHELLCODE_MAX_SIZE; // + bss_len;
    out_text_phdr->p_flags |= PF_W;
    out_data_phdr->p_flags |= PF_X;
    WRITE_FILE_ZEROES(bss_len, "file bss");

    Elf64_Shdr *text_shdr;
    if ((text_shdr = get_section_header_by_name(data, ".text")))
    {
        printf("[*] .text section will be packed\n");
        text_vstart = text_shdr->sh_addr; // le faire de facon dynamique (: encrypter la section qui contient l'entry point)
        text_start = out + text_shdr->sh_offset;
        text_len = text_shdr->sh_size;
    }
    else
    {
        printf("[*] no sections to pack (what 2pac ?)\n");
        Elf64_Phdr *interp = get_loadable_segment(data + ehdr->e_phoff, ehdr->e_phnum, PT_INTERP, 0); // TODO: le packing sans sections est pas bon
        text_vstart = interp->p_vaddr + interp->p_filesz;
        text_start = out + interp->p_offset + interp->p_filesz;
        text_len = (out_text_phdr->p_offset + out_text_phdr->p_filesz) - (interp->p_offset + interp->p_filesz);
    }

	// On genere la key et on l'ecrit dans le binaire
    generate_key(key, user_key);

    // on assemble le loader et on l'injecte
    loader_vstart = out_data_phdr->p_vaddr + out_data_phdr->p_filesz - SHELLCODE_MAX_SIZE;
    loader_len = write_loader(loader, loader_vstart, old_entry, text_vstart, text_len, key);
    (void)loader_len;
    WRITE_FILE(loader, (unsigned long)SHELLCODE_MAX_SIZE, "loader");
    printf("[+] loader injected at %#lx\n", loader_vstart);

    // set le nouvel entry point
    out_ehdr->e_entry = loader_vstart;
    printf("[+] new entry point: %#lx\n", loader_vstart);
    if (ehdr->e_shnum)
    {
        out_ehdr->e_shoff+= SHELLCODE_MAX_SIZE + bss_len;
        out_ehdr->e_shnum++;
    }

    // on copie ce qui est entre la fin de DATA et le debut des section headers
    WRITE_FILE(data + data_phdr->p_offset + data_phdr->p_filesz,
            (ehdr->e_shoff ? ehdr->e_shoff : old_size) - (data_phdr->p_offset + data_phdr->p_filesz), // copie jusque aux shdrs, ou a la fin si pas de shdrs
            "remaining");

    // on copie les section headers (+ le notre)
    if (ehdr->e_shnum)
    {
        WRITE_FILE(shdr, ehdr->e_shnum * sizeof(Elf64_Shdr), "section_headers");
        new_shdr.sh_name      = 0;
        new_shdr.sh_type      = SHT_PROGBITS;
        new_shdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
        new_shdr.sh_addr      = loader_vstart;
        new_shdr.sh_offset    = 0;
        new_shdr.sh_size      = SHELLCODE_MAX_SIZE;
        new_shdr.sh_link      = 0;
        new_shdr.sh_info      = 0;
        new_shdr.sh_addralign = 16;
        new_shdr.sh_entsize   = 0;
        WRITE_FILE(&new_shdr, sizeof(Elf64_Shdr), "new shdr");

        // on change les offset des sections header des sections qui ont ete bouges par le loader et le bss
        Elf64_Shdr *tmp_shdr = out + out_ehdr->e_shoff;
        Elf64_Half i;
        for (i = 0; i < out_ehdr->e_shnum; ++i)
        {
            if (tmp_shdr[i].sh_offset >= data_phdr->p_offset + data_phdr->p_filesz)
            {
                tmp_shdr[i].sh_offset += SHELLCODE_MAX_SIZE + bss_len;
            }
        }
    }

    printf("[+] packing %#lx-%#lx (%#lx bytes)\n", text_vstart, text_vstart + text_len, text_len);
    pack(text_start, text_len, key);

    printf("[*] elf size: %ld\n", cur - out);

    write_file("woody", out, cur - out);

    free(data);
    free(out);
    return 1;

/* err_free_data_out: */
    free(out);
err_free_data:
    free(data);
err:
    printf("[X] aborting !\n");
    return 0;
}

// BONI
// encryption en aes
// en/decryption + rapide en asm
// gestion dune clef utilisateur
// msg d'info lourds
// gestion des binaires deja packes
int main(int ac, char **av)
{
    if (ac >= 2)
    {
        if(!start(av[1], ac == 3 ? av[2] : NULL))
            return 1;
    }
    return 0;
}
