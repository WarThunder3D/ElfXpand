#include "menu_func.h"

static void load_section_map_fromfile(char* filename, elf_head_t* elf_head, elf_head_t* elf_second, int* sect_freespacevals, size_t* inject_array_size_out, inject_transfer_t*** inject_array_out);

void menu_main(elf_head_t* elf_head) {

	char operation;

	/*#######*/



	operation = '\0';
	while (operation != 'q') {
		eset = ELIST_SUCCESS;
		printf("Main menu: Ready for input. Type \"?\" for a list of operations.\n");
		MENUMAC_GETCHAR(operation);
		switch (operation) {
		case MENUOP_SHOWSECTIONS:
			menu_showsections(elf_head);
			break;
		case MENUOP_EXPAND:
			menu_expand(elf_head);
			break;
		case MENUOP_INJECT:
			menu_inject(elf_head);
			break;
		case MENUOP_PATCH:
			menu_patch(elf_head);
			break;
		case MENUOP_MAP:
			menu_map(elf_head);
			break;
		case MENUOP_OPTIONS:
			menu_printoperations();
			break;
		case MENUOP_QUIT:
			break;
		default:
			printf("Bad operation. Type a letter from the operations list.\n");
			break;
		}
	}

	//printf("Type in a section index to inspect it:\n");

}

void menu_printoperations() {
	printf("Operations:\n"
		MENUOP_SHOWSECTIONS_S" - show ELF sections\n"
		MENUOP_EXPAND_S" - expand a section\n"
		MENUOP_INJECT_S" - inject into ELF section at address from another ELF object file's section\n"
		MENUOP_PATCH_S" - patch an ELF section at address with a binary file\n"
		MENUOP_MAP_S" - load a map file for this ELF\n"
		MENUOP_OPTIONS_S" - show this operation page\n"
		MENUOP_QUIT_S" - quit\n"
	);
	//printf("Type the corresponding letter to perform an operation.\n");
}

void menu_showsections(elf_head_t* elf_head) {

	int i;

	/*#######*/

	printf("Sections:\n");
	for (i = 0; i < elf_head->sectable_count; ++i) {
		menusub_showsection(elf_head->sections[i]);
	}
}

void menusub_showsection(elf_sechead_t* section) {
	printf("%d: %s\n\tPC Offset: 0x%X | Size: 0x%X | Virtual Address Offset: 0x%X\n", section->index, section->section_name, section->sh_offset, section->sh_size, section->sh_addr);
}

void menumisc_printsectsize(elf_sechead_t* section) {
	int tmp_size = section->sh_size + getsectsize_withpad(section->sh_size);
	printf("Size of section \"%s\": 0x%X | With alignment padding: 0x%X\n", section->section_name, section->sh_size, tmp_size);
}

void menumisc_promptsect(elf_head_t* elf_head, char* custom_message) {
	char operation;

	/*#######*/

	if (custom_message == NULL)
		printf("Show section table?"MENU_YESNOOPTIONS"\n");
	else
		printf("%s"MENU_YESNOOPTIONS"\n", custom_message);
	IF_MENURESPONSE_ISYES(operation)
		menu_showsections(elf_head);
}

//NOTE: must free char* after usage
char* menumisc_getfilename(char* custom_message) {
	char* operation_finpoint;
	char* ohead;

	/*#######*/

	operation_finpoint = malloc(sizeof(char)*MENU_MAXCHAR);
	if (operation_finpoint == NULL)
		return terminate_error(ELIST_NOMEM);

	if (custom_message != NULL)
		printf("%s\n", custom_message);
	else
		printf("Enter a filename:\n");

	fgets(operation_finpoint, MENU_MAXCHAR - 1, stdin);
	operation_finpoint[MENU_MAXCHAR - 1] = '\0';
	for (ohead = operation_finpoint; *ohead != '\0'; ++ohead) {
		if (*ohead == '\n') *ohead = '\0';
	}

	return operation_finpoint;
}

int menumisc_sectindexselect(elf_head_t* elf_head, char* custom_message) {
	int sect_index;
	int operation_i;

	/*#######*/

	if (custom_message == NULL)
		printf("Enter a section index: (0-%d)\n", (elf_head->sectable_count - 1));
	else
		printf("%s (0-%d)\n", custom_message, (elf_head->sectable_count - 1));

	for (sect_index = -1; sect_index < 0;) {
		scanf(" %d", &operation_i);
		sect_index = operation_i;

		if (!(sect_index >= 0 && sect_index < elf_head->sectable_count)) {
			printf("Bad section index. Type a number from the above range.\n");
			sect_index = -1;
		}
	}
	printf("Selected section: \"%s\"\n", elf_head->sections[sect_index]->section_name);
	return sect_index;

}

int menumisc_display_ynsimple(char* custom_message) {
	char operation;

	/*#######*/

	if (custom_message == NULL)
		printf("Continue?"MENU_YESNOOPTIONS"\n");
	else
		printf("%s"MENU_YESNOOPTIONS"\n", custom_message);
	IF_MENURESPONSE_ISYES(operation)
		return true;
	else
		return false;
}

void menu_expand(elf_head_t* elf_head) {

	int i;

	char operation;
	int operation_i;

	int sect_index;
	int current_index;
	int new_size;
	int tmp_addr_a;
	int tmp_addr_b;
	int tmp_addr_c;
	int tmp_amount;
	int j;

	int* sect_indexshift;

	/*#######*/

	sect_indexshift = malloc(sizeof(int)*elf_head->sectable_count);
	memset(sect_indexshift, -1, elf_head->sectable_count);//BASEADDR_SECTIONARRAY_INVALID
	j = -1;

	if (true) {


		menumisc_promptsect(elf_head, NULL);
		sect_index = menumisc_sectindexselect(elf_head, "Enter a section index (number) to expand:");


		menumisc_printsectsize(elf_head->sections[sect_index]);
		printf("Enter the new size in hex:\n");
		do {
			scanf(" %x", &operation_i);
			new_size = operation_i;
			if (new_size == elf_head->sections[sect_index]->sh_size) {
				printf("The new size is identical to the old size. Reprompting input...\n");
			}
		} while (new_size == elf_head->sections[sect_index]->sh_size);

		//check for size trimming
		if (new_size < elf_head->sections[sect_index]->sh_size) {
			if (!menumisc_display_ynsimple("The new size is less than the old size! This will trim any excess data, resulting in data loss. Continue?"))
				return terminate_error(ELIST_EXIT);
		}
		else {
			//check for virtual address clash
			tmp_addr_a = elf_head->sections[sect_index]->sh_addr;
			tmp_addr_b = elf_head->sections[sect_index]->sh_addr + new_size;// +getsectsize_withpad(new_size);
			tmp_addr_b += getsectsize_withpad(tmp_addr_b);
			tmp_addr_c = elf_head->sections[sect_index]->sh_addr + elf_head->sections[sect_index]->sh_size;// +getsectsize_withpad(new_size);
			tmp_addr_c += getsectsize_withpad(tmp_addr_c);
			tmp_amount = tmp_addr_b - tmp_addr_c;

			current_index = elf_head->sections[sect_index]->index;
			for (i = 0; i < elf_head->sectable_count; ++i) {
				if (elf_head->sections[i]->index == current_index)
					continue;
				IF_ELFPARSE_NULLTYPE(elf_head->sections[i])
					continue;

				if (elf_head->sections[i]->sh_addr > tmp_addr_a && elf_head->sections[i]->sh_addr < tmp_addr_b) {

					printf("Section clash. Will be moving section \"%s\" at 0x%X.\n", elf_head->sections[i]->section_name, elf_head->sections[i]->sh_addr);

					++j;
					sect_indexshift[j] = i;


					// this assumes that sections are back-to-back with each other.
					tmp_addr_a = elf_head->sections[i]->sh_addr;// +tmp_amount;
					tmp_addr_b = elf_head->sections[i]->sh_addr + elf_head->sections[i]->sh_size + tmp_amount;
					//tmp_addr_b += getsectsize_withpad(tmp_addr_b);					


					/*
					printf("The new size will clash with another section in the virtual address space. (\"%s\" at 0x%X) Continue?"MENU_YESNOOPTIONS"\n", elf_head->sections[i]->section_name, elf_head->sections[i]->sh_addr);
					IF_MENURESPONSE_ISNO(operation)
					return terminate_error(ELIST_EXIT);
					*/

				}
			}

			// shift the clashing sections. must be done backwards.
			for (; j >= 0; --j) {
				elf_shift(elf_head, sect_indexshift[j], tmp_amount);
			}
		}
		elf_expand(elf_head, sect_index, new_size);
	}
	else {
		elf_shift(elf_head, 6, 0x50000);
	}








	if (!eset)
		elf_save(elf_head);

	free(sect_indexshift);

	return eset;
}

void menu_inject(elf_head_t* elf_head) {

	char* operation_s;
	elf_head_t* elf_second;
	//int sect_index_source;
	//int sect_index_dest;
	//int dest_addr;
	int source_size;
	size_t i;
	size_t j;
	int addr_dest;

	inject_transfer_t** inject_array;
	inject_transfer_t* inject_temp;
	size_t inject_array_size;

	int* sect_freespacevals;

	/*#######*/

	sect_freespacevals = malloc(sizeof(int)*elf_head->sectable_count);
	memset(sect_freespacevals, -1, elf_head->sectable_count);//BASEADDR_SECTIONARRAY_INVALID

	if (elf_head->map_list == NULL) {
		if (!menumisc_display_ynsimple("Continue without a map file? Without it, object files with external symbols will not transfer (relocate) correctly."))
			return terminate_error(ELIST_EXIT);
	}

	operation_s = menumisc_getfilename(MENUSTRING_INJECT_S1_READELF);
	if (eset)
		return;

	elf_second = load_elf(operation_s);
	free(operation_s);
	if (eset)
		return;


	menumisc_promptsect(elf_second, MENUSTRING_INJECT_S2_SHOWSECA);
	menumisc_promptsect(elf_head, MENUSTRING_INJECT_S4_SHOWSECB);

	if (menumisc_display_ynsimple(MENUSTRING_INJECT_S2A_USEMAP)) {

		operation_s = menumisc_getfilename(MENUSTRING_INJECT_S3A_READMAP);
		if (eset)
			return;

		load_section_map_fromfile(operation_s, elf_head, elf_second, sect_freespacevals, &inject_array_size, &inject_array);
		if (eset)
			return;

		free(operation_s);

	}
	else {

		inject_array_size = 0;
		inject_array = malloc(sizeof(inject_array));
		if (inject_array == NULL)
			return terminate_error(ELIST_NOMEM);

		do {
			inject_temp = malloc(sizeof(inject_transfer_t));
			if (inject_temp == NULL)
				return terminate_error(ELIST_NOMEM);

			inject_temp->sect_index_source = menumisc_sectindexselect(elf_second, MENUSTRING_INJECT_S3_INDEXGETA);
			menumisc_printsectsize(elf_second->sections[inject_temp->sect_index_source]);
			inject_temp->sect_index_dest = menumisc_sectindexselect(elf_head, MENUSTRING_INJECT_S5_INDEXGETB);
			source_size = elf_second->sections[inject_temp->sect_index_source]->sh_size + getsectsize_withpad(elf_second->sections[inject_temp->sect_index_source]->sh_size);
			inject_temp->dest_addr = menumisc_promptdestaddr(elf_head->sections[inject_temp->sect_index_dest], source_size);
			inject_temp->dest_base = elf_head->sections[inject_temp->sect_index_dest]->sh_addr;
			inject_temp->is_virtual = true;

			inject_array_size++;
			inject_array = realloc(inject_array, sizeof(inject_array)*(inject_array_size + 1));
			if (inject_array == NULL)
				return terminate_error(ELIST_NOMEM);
			inject_array[inject_array_size - 1] = inject_temp;
			inject_array[inject_array_size] = NULL;

		} while (menumisc_display_ynsimple("Add another section to inject?"));
	}








	elf_inject(elf_head, elf_second, inject_array);
	for (i = 0; i < inject_array_size; ++i)
		free(inject_array[i]);
	free(inject_array);
	free(sect_freespacevals);

	if (!eset)
		elf_save(elf_head);

	unload_elf(elf_second);
}

void operation_inject(elf_head_t* elf_head, char* second_elf_filename, char* section_map_filename) {

	char* operation_s;
	elf_head_t* elf_second;
	//int sect_index_source;
	//int sect_index_dest;
	//int dest_addr;
	int source_size;
	size_t i;
	size_t j;
	int addr_dest;

	inject_transfer_t** inject_array;
	inject_transfer_t* inject_temp;
	size_t inject_array_size;

	int* sect_freespacevals;

	/*#######*/

	sect_freespacevals = malloc(sizeof(int)*elf_head->sectable_count);
	memset(sect_freespacevals, -1, elf_head->sectable_count);//BASEADDR_SECTIONARRAY_INVALID

	if (elf_head->map_list == NULL) {
		return terminate_error(ELIST_INJECT_MAPFILEREQUIRED);
	}

	elf_second = load_elf(second_elf_filename);
	if (eset)
		return;

	load_section_map_fromfile(section_map_filename, elf_head, elf_second, sect_freespacevals, &inject_array_size, &inject_array);
	if (eset)
		return;

	elf_inject(elf_head, elf_second, inject_array);
	for (i = 0; i < inject_array_size; ++i)
		free(inject_array[i]);
	free(inject_array);
	free(sect_freespacevals);

	if (!eset)
		elf_save(elf_head);

	unload_elf(elf_second);
}

static void load_section_map_fromfile(char* filename, elf_head_t* elf_head, elf_head_t* elf_second, int* sect_freespacevals, size_t* inject_array_size_out, inject_transfer_t*** inject_array_out) {

	size_t i;
	size_t j;

	map_item** sectionmap_list;
	size_t sectionmap_count;
	char* sectionmap_destsect;
	char* sectionmap_sourcesect;
	bool sectionmap_vertfound;
	int sectionmap_indexdest;
	int sectionmap_indexsrc;

	inject_transfer_t* inject_temp;
	size_t inject_array_size;

	inject_transfer_t** inject_array;

	/*#######*/

	inject_array_size = 0;
	inject_array = malloc(sizeof(inject_array));
	if (inject_array == NULL)
		return terminate_error(ELIST_NOMEM);


	sectionmap_list = NULL;
	map_load(&sectionmap_list, filename);


	sectionmap_count = map_getcount(sectionmap_list);
	for (i = 0; i < sectionmap_count; ++i) {

		sectionmap_destsect = sectionmap_list[i]->map_name;
		sectionmap_sourcesect = sectionmap_list[i]->map_name;

		// names are parsed as the following: dest_sect_name|source_sect_name

		for (sectionmap_vertfound = false; !sectionmap_vertfound; sectionmap_sourcesect++) {
			if (*sectionmap_sourcesect == '\0') {
				// end of string reached without finding vertbar
				return terminate_error_str(ELIST_FILEMAPSECT_NODEST, sectionmap_list[i]->map_name);
			}
			else if (*sectionmap_sourcesect == '|') {
				*sectionmap_sourcesect = '\0';//destsect is correctly terminated
				sectionmap_vertfound = true;
			}
		}

		// get dest index
		for (j = 0; j < elf_head->sectable_count; ++j) {
			if (!strcmp(sectionmap_destsect, elf_head->sections[j]->section_name)) {
				sectionmap_indexdest = elf_head->sections[j]->index;
				break;
			}
		}
		if (j >= elf_head->sectable_count) {
			return terminate_error_str(ELIST_FILEMAPSECT_DESTSECTNOTFOUND, sectionmap_destsect);
		}


		if (!strcmp(sectionmap_sourcesect, MAPVALUE_FREESPACE_IDENTIFIER)) {
			//freespace value defined.
			sect_freespacevals[sectionmap_indexdest] = sectionmap_list[i]->map_value;
			continue;
		}

		// get source index
		for (j = 0; j < elf_second->sectable_count; ++j) {
			if (!strcmp(sectionmap_sourcesect, elf_second->sections[j]->section_name)) {
				sectionmap_indexsrc = elf_second->sections[j]->index;
				break;
			}
		}
		if (j >= elf_second->sectable_count) {
			return terminate_error_str(ELIST_FILEMAPSECT_SRCSECTNOTFOUND, sectionmap_sourcesect);
		}

		inject_temp = malloc(sizeof(inject_transfer_t));
		if (inject_temp == NULL)
			return terminate_error(ELIST_NOMEM);

		inject_temp->sect_index_source = sectionmap_indexsrc;
		inject_temp->sect_index_dest = sectionmap_indexdest;
		inject_temp->dest_addr = menumisc_getdestaddr(inject_temp, sect_freespacevals, elf_second->sections[sectionmap_indexsrc]->sh_size, sectionmap_list[i]->map_value);

		if (!(inject_temp->dest_addr >= elf_head->sections[sectionmap_indexdest]->sh_addr && inject_temp->dest_addr < (elf_head->sections[sectionmap_indexdest]->sh_addr + elf_head->sections[sectionmap_indexdest]->sh_size)))
			return terminate_error_str(ELIST_FILEMAPSECT_SECTOUTSIDE, sectionmap_sourcesect);

		inject_temp->dest_base = elf_head->sections[sectionmap_indexdest]->sh_addr;

		inject_temp->is_virtual = true;

		inject_array_size++;
		inject_array = realloc(inject_array, sizeof(inject_array)*(inject_array_size + 1));
		if (inject_array == NULL)
			return terminate_error(ELIST_NOMEM);
		inject_array[inject_array_size - 1] = inject_temp;
		inject_array[inject_array_size] = NULL;

	}

	free(sectionmap_list);
	*inject_array_out = inject_array;
	*inject_array_size_out = inject_array_size;
}

int menumisc_getdestaddr(inject_transfer_t* inject_details, int* sect_freespacevals, int increment_freespace_size, int fallback_destaddr) {

	int addr_dst;

	// ###### //

	addr_dst = fallback_destaddr;
	if (addr_dst == MAPVALUE_FREESPACE_VALUE) {
		if (BASEADDR_SECTIONARRAY_INVALID(sect_freespacevals[inject_details->sect_index_dest])) {
			terminate_error(ELIST_NM_MAPVALNOTFOUND);
			return;
		}

		addr_dst = sect_freespacevals[inject_details->sect_index_dest];
		//get the next freespace address here	
		sect_freespacevals[inject_details->sect_index_dest] += increment_freespace_size;
	}


	return addr_dst;
}

int menumisc_promptdestaddr(elf_sechead_t* dest_section, int source_size) {

	int operation_i;

	int dest_addr;
	int endaddr_temp;
	int tmp_dest_addr;

	/*#######*/

	endaddr_temp = dest_section->sh_addr + dest_section->sh_size;
	printf("Enter the virtual destination address in hex. Valid range: 0x%X-0x%X\n", dest_section->sh_addr, endaddr_temp - 1);
	for (;;) {
		scanf(" %x", &operation_i);
		dest_addr = operation_i;
		if (!(dest_addr >= dest_section->sh_addr&&dest_addr < endaddr_temp)) {
			printf("Not within virtual address range. Reprompting input...\n");
			continue;
		}

		tmp_dest_addr = dest_addr - dest_section->sh_addr;
		if (tmp_dest_addr + source_size >= dest_section->sh_size) {
			printf("At this address, the copied data will overflow the existing data. Try expanding the destination section first. Reprompting input...\n");
			continue;
		}

		return dest_addr;
	}
}

void menu_patch(elf_head_t* elf_head) {
	char* operation_s;

	FILE* input_file;
	byte* file_buffer;
	size_t file_size;

	int dest_addr;
	int sect_index_dest;

	/*#######*/

	//reading file
	operation_s = menumisc_getfilename(MENUSTRING_PATCH_S1_READBIN);
	if (eset)
		return;

	input_file = fopen(operation_s, "r+b");
	free(operation_s);
	if (input_file == NULL)
		return terminate_error(ELIST_FILECANNOTOPEN);

	fseek(input_file, 0, SEEK_END);
	file_size = ftell(input_file);
	fseek(input_file, 0, SEEK_SET);

	file_buffer = (byte*)malloc(file_size + 1);
	if (file_buffer == NULL)
		return terminate_error(ELIST_FILELOADNOMEM);

	fread(file_buffer, file_size, sizeof(byte), input_file);
	fclose(input_file);

	//

	printf("File size: 0x%X\n", file_size);
	menumisc_promptsect(elf_head, MENUSTRING_PATCH_S2_SHOWSEC_DEST);
	sect_index_dest = menumisc_sectindexselect(elf_head, MENUSTRING_PATCH_S3_INDEXGET_DEST);

	dest_addr = menumisc_promptdestaddr(elf_head->sections[sect_index_dest], file_size);
	elf_patch(elf_head, file_buffer, sect_index_dest, dest_addr, file_size, true);
	if (eset)
		elf_save(elf_head);

	free(file_buffer);
}

void menu_map(elf_head_t* elf_head) {
	char* operation_s;



	//map_item** map_array;

	/*#######*/


	operation_s = menumisc_getfilename(MENUSTRING_MAP_S1_READTXT);
	if (eset)
		return;
	map_load(&elf_head->map_list, operation_s);
	free(operation_s);
}