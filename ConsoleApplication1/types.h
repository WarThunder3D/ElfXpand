#ifndef DEF_TYPES
#define DEF_TYPES

#include <stdint.h>

typedef uint8_t byte;

struct headflags_s {
	char* mapfile;
	int read;
	int menu_immediate_operation; //MENU_IMMEDIATEOPERATION

	union {
		struct {
			char* source_object_file;
			char* section_map_file;
		} inject;
	} immediateop_params;
	
};

//NOTE: unload_elf should be updated to free memory for allocated members

typedef struct {
	char* section_name;
	byte* section_data;
	int index;
	union {
		int* relocatetable_index;
		//int* symboltable_index;
	};


	int sh_name;
	int sh_type;
	int sh_flags;
	int sh_addr;
	int sh_offset;
	int sh_size;
	int sh_link;
	int sh_info;
	int sh_addralign;
	int sh_entsize;
} elf_sechead_t;


typedef struct {
	char* map_name;
	uint32_t map_value;
} map_item;

typedef struct {
	byte* header_data;
	char* filename;

	map_item** map_list;

	size_t recompiled_size;

	int endianness;
	int bit_size;
	int processor;
	int head_size;
	//int pg_head_table;
	int sectable_offset;
	int sectable_count;
	int sectable_size;
	int sectable_nameoffset;
	elf_sechead_t** sections;
} elf_head_t;

typedef struct {
	int sect_index_source;
	int sect_index_dest;
	int dest_addr;
	int dest_base;
	int is_virtual;
} inject_transfer_t;

typedef struct rela_s {
	int r_offset;
	int r_info;
	int r_addend;
	struct rela_s* next;
} rela_t;

enum COMPILER_USE {
	CUSE_GCC
};

enum MENU_IMMEDIATEOPERATION {
	MENUIMMOP_NONE,
	MENUIMMOP_INJECT,
};


#endif