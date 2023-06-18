#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	int fd = open(exe_file_name, O_RDONLY);
	
	Elf64_Ehdr ElfHeader;
	read(fd, &ElfHeader, sizeof(ElfHeader));

	if(ElfHeader.e_type != ET_EXEC){
		*error_val = -3;
		close(fd);
		return 0;
	}

	Elf64_Shdr SH_StringTableHeader;
	lseek(fd, ElfHeader.e_shoff + ElfHeader.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
	read(fd, &SH_StringTableHeader, sizeof(SH_StringTableHeader));

	char SH_StringTable[SH_StringTableHeader.sh_size];
 	lseek(fd, SH_StringTableHeader.sh_offset, SEEK_SET);
	read(fd, SH_StringTable, SH_StringTableHeader.sh_size);

	// finding the symbol table
	Elf64_Shdr SectionHeader;
	Elf64_Shdr SymbolTableHeader;
	Elf64_Shdr StringTableHeader;
	lseek(fd, ElfHeader.e_shoff, SEEK_SET);
	bool found_symtab = false;
	bool found_strtab = false;

	for(int i = 0; i < ElfHeader.e_shnum; i++){
		read(fd, &SectionHeader, sizeof(SectionHeader));
		if(strcmp(SH_StringTable + SectionHeader.sh_name, ".symtab") == 0){
			found_symtab = true;
			SymbolTableHeader = SectionHeader;
		}
		else if(strcmp(SH_StringTable + SectionHeader.sh_name, ".strtab") == 0){
			found_strtab = true;
			StringTableHeader = SectionHeader;
		}
		lseek(fd, ElfHeader.e_shoff + (i+1) * sizeof(Elf64_Shdr), SEEK_SET);
	}

	if(!found_strtab || !found_symtab){
		*error_val = -1;
		close(fd);
		return 0;
	}

	char StringTable[StringTableHeader.sh_size];
	lseek(fd, StringTableHeader.sh_offset, SEEK_SET);
	read(fd, StringTable, StringTableHeader.sh_size);

	// printf("~~~~~~~~~\n");

	// reading the symbol table
	// might be local, global, neither or both
	Elf64_Sym Symbol;
	Elf64_Sym GlobalSymbol;
	lseek(fd, SymbolTableHeader.sh_offset, SEEK_SET);
	bool local = false;
	bool global = false;

	for(int i = 0; i < SymbolTableHeader.sh_size / sizeof(Elf64_Sym); i++){
		read(fd, &Symbol, sizeof(Symbol));
		// printf("symbol name: %s\n", StringTable + Symbol.st_name);
		if(strcmp(StringTable + Symbol.st_name, symbol_name) == 0){
			// printf("found symbol %s\n", symbol_name);
			if(ELF64_ST_BIND(Symbol.st_info) == 0){
				local = true;
			}
			else if(ELF64_ST_BIND(Symbol.st_info) == 1){
				global = true;
				GlobalSymbol = Symbol;
			}
		}
	}

	// printf("local = %d, global = %d\n", local, global);

	if(!local && !global){
		*error_val = -1;
		close(fd);
		return 0;
	}

	if(local && !global){
		*error_val = -2;
		close(fd);
		return 0;
	}

	// symbol is global (and maybe local)
	// if it's not defined in the executable, it's defined in a shared library
	// checking if it's defined in the executable
	if(GlobalSymbol.st_shndx == 0){
		*error_val = -4;
		close(fd);
		return 0;
	}

	// symbol is defined in the executable
	*error_val = 1;
	close(fd);
	return GlobalSymbol.st_value;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}