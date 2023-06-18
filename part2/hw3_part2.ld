/* TODO: complete the script */


SECTIONS
{
 
  . = 0x60000;
  .data : 
  {
	*(.data)
	*(.bss)
  } :data 

  //TODO: add other sections
}
