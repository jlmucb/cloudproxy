#ifndef ELF64_H_
#define ELF64_H_
struct elf64_hdr {
    unsigned char e_ident[16];
    uint16_t    e_type;
    uint16_t    e_machine;
    uint32_t    e_version;
    uint64_t    e_entry;
    uint64_t    e_phoff;
    uint64_t    e_shoff;
    uint32_t    e_flags;
    uint16_t    e_ehsize;
    uint16_t    e_phentsize;
    uint16_t    e_phnum;
    uint16_t    e_shentsize;
    uint16_t    e_shnum;
    uint16_t    e_shstrndx;
};

typedef struct elf64_hdr elf64_hdr;


#define ELF64_PT_LOAD 1

struct elf64_phdr {
    uint32_t    p_type;
    uint32_t    p_flags;
    uint64_t    p_offset;
    uint64_t    p_vaddr;
    uint64_t    p_paddr;
    uint64_t    p_filesz;
    uint64_t    p_memsz;
    uint64_t    p_align;
    
};
typedef struct elf64_phdr elf64_phdr;

#endif
