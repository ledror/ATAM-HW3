/* TODO: complete the script */

PHDRS
{
  text PT_LOAD FLAGS(3);
  data PT_LOAD FLAGS(6);
  rodata PT_LOAD FLAGS(5);
}

SECTIONS
{
  . = 0x400000;
  .text :
  {
    *(.text)
  } :text

  . = 0x60000;
  .data : 
  {
	*(.data)
	*(.bss)
  } :data

  . = 0x80000000;
  .rodata :
  {
    *(.rodata)
  } :rodata
}

ENTRY(_hw3_unicorn)

EXTERN(purple)
EXTERN(white)

