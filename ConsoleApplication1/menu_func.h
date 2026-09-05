#ifndef DEF_MENU_FUNC
#define DEF_MENU_FUNC

#include <stdint.h>
#include <ctype.h>

#include "types.h"
#include "errorhandler.h"
#include "elf_parse.h"

#define MENUSTRING_OPEN_S1_READELF "Enter a path to the ELF:"

#define MENUSTRING_INJECT_S1_READELF "Enter a filename to a second ELF/object file for reading:"
#define MENUSTRING_INJECT_S2_SHOWSECA "Show this ELF's section table?"
#define MENUSTRING_INJECT_S2A_USEMAP "Use a map file for the sections?"
#define MENUSTRING_INJECT_S3A_READMAP "Enter the filename for the section map:"
#define MENUSTRING_INJECT_S4A_INDEXGETB "Enter the destination section index to use for all source sections:"
#define MENUSTRING_INJECT_S3_INDEXGETA "Enter the section index from the file (will be the source section, copying entire section):"
#define MENUSTRING_INJECT_S4_SHOWSECB "Show destination (opened) ELF's section table?"
#define MENUSTRING_INJECT_S5_INDEXGETB "Enter the destination section index for the existing ELF:"

#define MENUSTRING_PATCH_S1_READBIN "Enter a filename for a file to patch:"
#define MENUSTRING_PATCH_S2_SHOWSEC_DEST "Show destination (opened) ELF's section table?"
#define MENUSTRING_PATCH_S3_INDEXGET_DEST "Enter the destination index from the ELF:"

#define MENUSTRING_MAP_S1_READTXT "Enter a filename for the map file:"

#define MENU_MAXCHAR 255
#define CHARBUFF_SMALL 0x20

#define MENU_YESNOOPTIONS " y/n:"
#define MENU_YES 'y'

#define MENUOP_QUIT 'q'
#define MENUOP_QUIT_S "q"

#define MENUOP_EXPAND 'e'
#define MENUOP_EXPAND_S "e"

#define MENUOP_INJECT 'i'
#define MENUOP_INJECT_S "i"

#define MENUOP_PATCH 'p'
#define MENUOP_PATCH_S "p"

#define MENUOP_MAP 'm'
#define MENUOP_MAP_S "m"

#define MENUOP_OPTIONS '?'
#define MENUOP_OPTIONS_S "?"

#define MENUOP_SHOWSECTIONS 's'
#define MENUOP_SHOWSECTIONS_S "s"


#define CHAR_EXHAUST(c) while (c != '\n' && getchar() != '\n')
#define MENUMAC_GETCHAR(c) scanf(" %c", &c);CHAR_EXHAUST(c)
#define IF_MENURESPONSE_ISYES(c) MENUMAC_GETCHAR(c);if (c == MENU_YES)
#define IF_MENURESPONSE_ISNO(c) MENUMAC_GETCHAR(c);if (c != MENU_YES)

void menu_main(elf_head_t* elf_head);

void menu_printoperations();
void menu_showsections(elf_head_t* elf_head);
void menusub_showsection(elf_sechead_t* section);

void menu_expand(elf_head_t* elf_head);
void menu_inject(elf_head_t* elf_head);
void menu_patch(elf_head_t* elf_head);
void menu_map(elf_head_t* elf_head);

void operation_inject(elf_head_t* elf_head, char* second_elf_filename, char* section_map_filename);

char* menumisc_getfilename(char* custom_message);
void menumisc_promptsect(elf_head_t* elf_head, char* custom_message);
void menumisc_printsectsize(elf_sechead_t* section);

int menumisc_sectindexselect(elf_head_t* elf_head, char* custom_message);
int menumisc_promptdestaddr(elf_sechead_t* dest_section, int source_size);
int menumisc_getdestaddr(inject_transfer_t* inject_details, int* sect_freespacevals, int increment_freespace_size, int fallback_destaddr);
int menumisc_display_ynsimple(char* custom_message);

#endif