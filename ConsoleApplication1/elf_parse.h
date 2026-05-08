#ifndef DEF_ELF_PARSE
#define DEF_ELF_PARSE


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "types.h"
#include "errorhandler.h"
#include "misc_func.h"
#include "menu_func.h"
#include "elf.h"
#include <string.h>
#include <stdbool.h>

#define MANGLETYPE_GCC_BEGIN 'Z'
#define MANGLETYPE_GCC_NAMESPACE 'N'
#define MANGLETYPE_GCC_END 'E'

#define MAPVALUE_FREESPACE_IDENTIFIER "freespace"
#define MAPVALUE_FREESPACE_VALUE (-1)

#define ELFPARSESTRING_INJECT_COPYRESULT "PC:0x%X/VA:0x%X -> PC:0x%X/VA:0x%X"
#define ELFPARSESTRING_PATCH_COPYRESULT "BIN -> PC:0x%X/VA:0x%X"

#define CONVERT_VIRTTOINDEX_ADDRESS(b,d,s) if (b) d -= s->sh_addr

#define FUNC_RESIZEMAP(map,size) map = realloc(map, sizeof(map_item*)*(size + 1));	map[size] = NULL
#define FUNC_INITLINEBUFFER(l,s,li) s = MENU_MAXCHAR, l = malloc(s),li = 0

#define IF_ELFPARSE_NULLTYPE(s) if (s->sh_type == ELFTYPE_NULL)
#define IF_ELFPARSE_NOWRITETYPE(s) if (s->sh_type == ELFTYPE_NULL || s->sh_type == ELFTYPE_NOBITS)
#define IF_ELFPARSE_RELOCATETYPE(s) if (s->sh_type == ELFTYPE_RELA || s->sh_type == ELFTYPE_REL)
#define BASEADDR_SECTIONARRAY_INVALID(s) (s<0)
#define ehead_bitsize_convert(e) e==2
#define ehead_endian_convert(e) e==2
#define ELFPARSE_ISRELA(s) (s->sh_type==ELFTYPE_RELA)

elf_head_t* load_elf(char* filename);
void unload_elf(elf_head_t* elf_head);
elf_head_t* validate_elf(byte* file_buffer, size_t file_size);

void elf_expand(elf_head_t* elf_head, int section_index, int section_size);
void elf_shift(elf_head_t* elf_head, int section_index, int shift_amount);
void elf_recalculate_offsets(elf_head_t* elf_head);
void elf_save(elf_head_t* elf_head);
void elf_inject(elf_head_t* elf_dst, elf_head_t* elf_src, inject_transfer_t** inject_array);
void elf_adjustrelocate_data(elf_head_t* elf_head, inject_transfer_t** inject_array, int inject_index);
int elf_relocparse_ppc(int addr_temp, byte r_type, int new_basevirtaddr, int relativeaddr, bool be);
void elf_mergerelocate_data(elf_head_t* elf_dst, elf_head_t* elf_src, inject_transfer_t** inject_array);
void elf_patch(elf_head_t* elf_dst, byte* bin_src, int sect_dst, int addr_dst, int src_size, bool addr_dst_isvirtual);

int getsectsize_withalign(elf_sechead_t* section);
int getsectsize_withpad(int f_index);
int* getsectindexorder_offset(elf_head_t* elf_head);

int esort_offset(const void* a, const void* b);

void map_load(map_item*** map_refarray, char* fileuse);
void map_unload(map_item*** map_refarray);
void map_add(map_item*** map_refarray, size_t map_array_size, FILE* input_file);
size_t map_getcount(map_item** map_refarray);

char* demangle_name(char* input, enum COMPILER_USE cuse);

#endif