/* TODO: complete the script */

PHDRS
{
  /* FLAGS sets the p_flags member of the program header. */
  /*  PF_X = 1
      PF_W = 2
      PF_R = 4
  */
  text PT_LOAD FLAGS(3); /* PF_X | PF_W */
  data PT_LOAD FLAGS(6); /* PF_W | PF_R */
  rodata PT_LOAD FLAGS(5); /* PF_R | PF_X */
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

