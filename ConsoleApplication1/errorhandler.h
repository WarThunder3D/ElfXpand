#ifndef DEF_ERROR
#define DEF_ERROR

#include <stdlib.h>
#include <stdio.h>
#include "menu_func.h"

enum ERROR_LIST {
	ELIST_SUCCESS,
	ELIST_CONTINUE,
	ELIST_EXIT,
	ELIST_NOARGUMENTS,
	ELIST_NOFILENAME,
	ELIST_BADARGUMENT,
	ELIST_LOAD_MAP_BADARGUMENT,
	ELIST_FILEGIVEN,
	ELIST_FILECANNOTOPEN,
	ELIST_FILELOADNOMEM,
	ELIST_ELFHEAD_BADSIZE,
	ELIST_ELFHEAD_BADMAGIC,
	ELIST_ELFHEAD_NOSECT,
	ELIST_ELFSECTAB_BADSIZE,
	ELIST_ELFSECTAB_BADSIZESEC,
	ELIST_ELFSECTAB_NONAMETABLE,
	ELIST_FILECANNOTOPENOUT,
	ELIST_NOMEM,
	ELIST_RELOC_UNKNOWNTYPE,
	ELIST_RELOC_UNKNOWNCOMMAND,
	ELIST_RELOC_UNKNOWNBASE,
	ELIST_RELOC_SOURCENF,
	ELIST_NM_UNKNOWNCOMPILER,
	ELIST_NM_UNKNOWNTYPE,
	ELIST_NM_FAILED,
	ELIST_NM_MAPVALNOTFOUND,
	ELIST_FILEMAP_TOOMANYARGUMENTS,
	ELIST_FILEMAP_VALNOTSPECIFIED,
	ELIST_FILEMAP_VALNOTNUMBER,
	ELIST_FILEMAP_VALNOTSYMBOL,
	ELIST_FILEMAPSECT_SRCSECTNOTFOUND,
	ELIST_FILEMAPSECT_DESTSECTNOTFOUND,
	ELIST_FILEMAPSECT_SECTOUTSIDE,
	ELIST_FILEMAPSECT_NODEST,
	ELIST_FILEMAPSECT_NOFREESP,
	ELIST_RELOCMERGE_DESTSYMNOTFOUND
};

static const char* ERROR_LIST_STRINGS[] = {
	[ELIST_SUCCESS] = "",
	[ELIST_CONTINUE] = "Continuing...",
	[ELIST_EXIT] = "Returning...",
	[ELIST_NOARGUMENTS] = "No arguments provided.",
	[ELIST_NOFILENAME] = "No filename provided.",
	[ELIST_BADARGUMENT] = "Bad argument given.",
	[ELIST_LOAD_MAP_BADARGUMENT] = "No map file provided with map import argument.",//MENUOP_MAP_S
	[ELIST_FILEGIVEN] = "Filename already given.",
	[ELIST_FILECANNOTOPEN] = "Cannot open file.",
	[ELIST_FILELOADNOMEM] = "Insufficient memory.",
	[ELIST_ELFHEAD_BADSIZE] = "Bad file size.",
	[ELIST_ELFHEAD_BADMAGIC] = "Not an ELF file.",
	[ELIST_ELFHEAD_NOSECT] = "No section table found.",
	[ELIST_ELFSECTAB_BADSIZE] = "Bad file size.",
	[ELIST_ELFSECTAB_BADSIZESEC] = "Bad file size.",
	[ELIST_ELFSECTAB_NONAMETABLE] = "No name section to read section names from.",
	[ELIST_FILECANNOTOPENOUT] = "Cannot open original file for writing. Returning...",
	[ELIST_NOMEM] = "Insufficient memory.",
	[ELIST_RELOC_UNKNOWNTYPE] = "Unsupported processor type.",
	[ELIST_RELOC_UNKNOWNCOMMAND] = "Unsupported relocation command.",
	[ELIST_RELOC_UNKNOWNBASE] = "Base address not set for section",
	[ELIST_RELOC_SOURCENF] = "Section index in source file not found. Is it included in the map file?",
	[ELIST_NM_UNKNOWNCOMPILER] = "Unknown compiler format.",
	[ELIST_NM_UNKNOWNTYPE] = "Unknown mangled name type.",
	[ELIST_NM_FAILED] = "Name mangling failed.",
	[ELIST_NM_MAPVALNOTFOUND] = "Symbol not found within map file:",
	[ELIST_FILEMAP_TOOMANYARGUMENTS] = "Too many arguemnts on map line.",
	[ELIST_FILEMAP_VALNOTSPECIFIED] = "Map value not specified.",
	[ELIST_FILEMAP_VALNOTNUMBER] = "Map value not a number.",
	[ELIST_FILEMAPSECT_SRCSECTNOTFOUND] = "Source section name not found:",
	[ELIST_FILEMAPSECT_DESTSECTNOTFOUND] = "Destination section name not found:",
	[ELIST_FILEMAPSECT_SECTOUTSIDE] = "Section destination address was outside the bounds of the destination section:",
	[ELIST_FILEMAPSECT_NODEST] = "No destination section specified in map name. Formatting must resemble this (destsect|sourcesect):",
	[ELIST_FILEMAPSECT_NOFREESP] = "Freespace not defined.",
	[ELIST_RELOCMERGE_DESTSYMNOTFOUND]="Could not find appropriate symbol table to use for new relocation entry."
};

void* terminate_error(enum ERROR_LIST error);
void* terminate_error_no(enum ERROR_LIST error, int no);
void* terminate_error_hxno(enum ERROR_LIST error, int no);
void* terminate_error_str(enum ERROR_LIST error, char* str);


enum ERROR_LIST eset;

#endif