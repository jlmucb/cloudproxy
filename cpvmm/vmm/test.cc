/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

typedef long long unsigned u64;
typedef unsigned u32;
typedef short unsigned u16;
typedef unsigned char u8;

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include "elf.h"
#include "sys/stat.h"



void PrintElf(Elf32_Ehdr* elf) {
  int i;

  printf("magic number: ");
  for(i=0; i<16; i++)
    printf("%02x ", elf->e_ident[i]);
  printf("\n");
  printf("Type: %04x\n", elf->e_type);
  printf("Machine: %04x\n", elf->e_machine);
  printf("Version: %04x\n", elf->e_version);
  if(elf->e_machine==0x3e) {
    Elf64_Ehdr* elf64= (Elf64_Ehdr*) elf;
    printf("Entry point: %016lx\n", (long int)elf64->e_entry);
    printf("Program header: %16lx\n", (long int)elf64->e_phoff);
    printf("Section header: %16lx\n", (long int)elf64->e_shoff);
    printf("Flags: %08x\n", elf64->e_flags);
    printf("Size of this header: %d\n", elf64->e_ehsize);
    printf("Size of program header table: %d\n", elf64->e_phentsize);
    printf("Number of entries: %d\n", elf64->e_phnum);
    printf("Size of section header table: %d\n", elf64->e_shentsize);
    printf("Number of entries: %d\n", elf64->e_shnum);
    printf("section name entry: %d\n", elf64->e_shstrndx);
  } else {
    printf("Entry point: %08x\n", elf->e_entry);
    printf("Program header: %08x\n", elf->e_phoff);
    printf("Section header: %08x\n", elf->e_shoff);
    printf("Flags: %08x\n", elf->e_flags);
    printf("Size of this header: %d\n", elf->e_ehsize);
    printf("Size of program header table: %d\n", elf->e_phentsize);
    printf("Number of entries: %d\n", elf->e_phnum);
    printf("Size of section header table: %d\n", elf->e_shentsize);
    printf("Number of entries: %d\n", elf->e_shnum);
    printf("section name entry: %d\n", elf->e_shstrndx);
  }
}


bool get_evmm64_parameters(u64 start, u64* base, u64* size)
{
  Elf32_Ehdr* elf= (Elf32_Ehdr*) start;
  Elf32_Phdr* program_header= (Elf32_Phdr*)(start+(u64)elf->e_phoff);

  printf("\nevmm_parameters, filesize: %d\n", program_header->p_filesz);

  *base= start+(u64)759753;
  return true;
}


int main(int an, char** av) {
  struct stat  stat_block;
  bool   bootstrap= false;
  int    i;

  if(an<2) {
    printf("Wrong number of arguments\n");
    return 1;
  }

  if(stat(av[1], &stat_block)<0) {
    printf("cant stat %s\n", av[1]);
    return 1;
  }

  int filesize= stat_block.st_size;
  printf("%s is %d bytes long\n", av[1], filesize);

  for(i=0;i<an;i++)
    if(strcmp(av[i], "-b")==0)
      bootstrap= true;

  u64*  base= (u64*)malloc(filesize);
  if(base==NULL) {
    printf("cant malloc\n");
    return 1;
  }

  int read_desc= open(av[1], O_RDONLY);
  if(read_desc<0) {
    printf("can't open %s for reading\n", av[1]);
    return 1;
  }

  if(read(read_desc, base, filesize)<filesize) {
    printf("cant read %s\n", av[1]);
    return 1;
  }

  Elf32_Ehdr* elf= (Elf32_Ehdr*) base;
  PrintElf(elf);

  if(!bootstrap)
    return 0;

  u64   evmmbase= 0ULL;
  u64   evmmsize= 0ULL;

  if(!get_evmm64_parameters((u64)base, &evmmbase, &evmmsize)) {
    printf("Cant get evmm base\n");
    return 1;
  }

  printf("\nEvmm image %016lx %ld\n", (long int)evmmbase, (long int)evmmsize);
  PrintElf((Elf32_Ehdr*) evmmbase);

  return 0; 
}

