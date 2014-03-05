#define EI_NIDENT 16

struct Elf64_hdr {
    unsigned char e_ident[EI_NIDENT];
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
