OUTPUT_FORMAT(elf64-x86-64);
SECTIONS
{
  . = 0x70000000;
  _start_evmm_text = .;
  .text : { *(.text) }
  .rodata : { *(.rodata) }
  .data : { *(.data) }
  .bss : { *(.bss) }
  _end_evmm_bss = .;
}
