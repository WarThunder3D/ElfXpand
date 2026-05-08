#include "elf_parse.h"
#include <errno.h>


#include "cxx/demangle.h"

elf_head_t* load_elf(char* filename) {
	elf_head_t* elf_head;

	FILE* input_file;
	byte* file_buffer;
	size_t file_size;


	input_file = fopen(filename, "r+b");
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

	elf_head = validate_elf(file_buffer, file_size);
	free(file_buffer);
	if (eset) {
		printf("\"%s\" failed to read.\n", filename);
	}
	else {
		elf_head->filename = filename;
		printf("ELF file \"%s\" read successfully.\n", filename);
	}

	return elf_head;
}

void unload_elf(elf_head_t* elf_head) {
	int i;

	/*#######*/

	for (i = 0; i < elf_head->sectable_count; ++i) {
		free(elf_head->sections[i]->section_name);
		free(elf_head->sections[i]->section_data);
	}
	free(elf_head->header_data);
	free(elf_head);
}

elf_head_t* validate_elf(byte* file_buffer, size_t file_size) {

	elf_head_t* elf_head;

	int f_index;
	int sec_index;
	int st_len;
	char* st_offs;
	int tmp_index;


	/*#######*/

	elf_head = malloc(sizeof(elf_head_t));
	if (elf_head == NULL)
		return terminate_error(ELIST_NOMEM);

	if (file_size < 0x40)
		return terminate_error(ELIST_ELFHEAD_BADSIZE);

	if (file_buffer[ELFLOC_HEAD_MAGIC] != 0x7F ||
		file_buffer[ELFLOC_HEAD_MAGIC + 1] != 0x45 ||
		file_buffer[ELFLOC_HEAD_MAGIC + 2] != 0x4C ||
		file_buffer[ELFLOC_HEAD_MAGIC + 3] != 0x46
		)
		return terminate_error(ELIST_ELFHEAD_BADMAGIC);

	elf_head->bit_size = file_buffer[ELFLOC_HEAD_BITSIZE];
	elf_head->endianness = file_buffer[ELFLOC_HEAD_ENDIANNESS];
	elf_head->processor = get16bit(file_buffer, ELFLOC_HEAD_PROCESSOR, ehead_endian_convert(elf_head->endianness));

	elf_head->head_size = get16bit(file_buffer, ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_HEAD_SIZE64 : ELFLOC_HEAD_SIZE32, ehead_endian_convert(elf_head->endianness));

	//elf_head->pg_head_table = get32bit(file_buffer, ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_HEAD_TABLE_PG_O64 : ELFLOC_HEAD_TABLE_PG_O32, ehead_endian_convert(elf_head->endianness));
	elf_head->sectable_offset = get32bit(file_buffer, ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_HEAD_TABLE_SEC_O64 : ELFLOC_HEAD_TABLE_SEC_O32, ehead_endian_convert(elf_head->endianness));
	elf_head->sectable_count = get16bit(file_buffer, ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_HEAD_TABLE_SEC_C64 : ELFLOC_HEAD_TABLE_SEC_C32, ehead_endian_convert(elf_head->endianness));
	elf_head->sectable_size = get16bit(file_buffer, ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_HEAD_TABLE_SEC_S64 : ELFLOC_HEAD_TABLE_SEC_S32, ehead_endian_convert(elf_head->endianness));
	elf_head->sectable_nameoffset = get16bit(file_buffer, ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_HEAD_TABLE_SEC_N64 : ELFLOC_HEAD_TABLE_SEC_N32, ehead_endian_convert(elf_head->endianness));

	if (!elf_head->sectable_offset)
		return terminate_error(ELIST_ELFHEAD_NOSECT);

	if (file_size < (size_t)(elf_head->sectable_offset + (elf_head->sectable_count*elf_head->sectable_size)))
		return terminate_error(ELIST_ELFSECTAB_BADSIZE);

	elf_head->header_data = malloc(elf_head->head_size);
	if (elf_head->header_data == NULL)
		return terminate_error(ELIST_NOMEM);
	memcpy(elf_head->header_data, file_buffer, elf_head->head_size);

	elf_head->sections = malloc(sizeof(elf_sechead_t*)*elf_head->sectable_count);
	if (elf_head->sections == NULL)
		return terminate_error(ELIST_NOMEM);



	f_index = elf_head->sectable_offset;
	for (sec_index = 0; sec_index < elf_head->sectable_count; ++sec_index) {
		elf_head->sections[sec_index] = malloc(sizeof(elf_sechead_t));
		if (elf_head->sections[sec_index] == NULL)
			return terminate_error(ELIST_NOMEM);
		elf_head->sections[sec_index]->index = sec_index;
		elf_head->sections[sec_index]->sh_name = get32bit(file_buffer, f_index + ELFLOC_SEC_NAME, ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_type = get32bit(file_buffer, f_index + ELFLOC_SEC_TYPE, ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_flags = get32bit(file_buffer, f_index + ELFLOC_SEC_ATTR, ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_addr = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_VADDR64 : ELFLOC_SEC_VADDR32), ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_offset = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_OFFSET64 : ELFLOC_SEC_OFFSET32), ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_size = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_SIZE64 : ELFLOC_SEC_SIZE32), ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_link = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_LINK64 : ELFLOC_SEC_LINK32), ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_info = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_INFO64 : ELFLOC_SEC_INFO32), ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_addralign = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_ALIGN64 : ELFLOC_SEC_ALIGN32), ehead_endian_convert(elf_head->endianness));
		elf_head->sections[sec_index]->sh_entsize = get32bit(file_buffer, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_ENT64 : ELFLOC_SEC_ENT32), ehead_endian_convert(elf_head->endianness));

		IF_ELFPARSE_NOWRITETYPE(elf_head->sections[sec_index]);
		else if (file_size < (size_t)(elf_head->sections[sec_index]->sh_offset + elf_head->sections[sec_index]->sh_size))
			return terminate_error(ELIST_ELFSECTAB_BADSIZESEC);


		elf_head->sections[sec_index]->relocatetable_index = NULL;

		f_index += elf_head->sectable_size;
	}

	if (elf_head->sectable_nameoffset >= elf_head->sectable_count)
		return terminate_error(ELIST_ELFSECTAB_NONAMETABLE);

	for (sec_index = 0; sec_index < elf_head->sectable_count; ++sec_index) {
		//name finding

		st_offs = file_buffer + elf_head->sections[elf_head->sectable_nameoffset]->sh_offset + elf_head->sections[sec_index]->sh_name;
		st_len = strlen(st_offs);
		elf_head->sections[sec_index]->section_name = (char*)malloc(st_len + 1);
		if (elf_head->sections[sec_index]->section_name == NULL)
			return terminate_error(ELIST_NOMEM);
		strcpy(elf_head->sections[sec_index]->section_name, st_offs);

		//data copying
		elf_head->sections[sec_index]->section_data = malloc(elf_head->sections[sec_index]->sh_size);
		if (elf_head->sections[sec_index]->section_data == NULL)
			return terminate_error(ELIST_NOMEM);
		memcpy(elf_head->sections[sec_index]->section_data, file_buffer + elf_head->sections[sec_index]->sh_offset, elf_head->sections[sec_index]->sh_size);

		//relocation table
		IF_ELFPARSE_RELOCATETYPE(elf_head->sections[sec_index]) {
			tmp_index = elf_head->sections[sec_index]->sh_info;
			//sh_info has index (data <- REL)
			if (tmp_index >= 0 && tmp_index < elf_head->sectable_count) {
				IF_ELFPARSE_NOWRITETYPE(elf_head->sections[tmp_index])
					continue;
				if (elf_head->sections[tmp_index]->relocatetable_index != NULL)
					printf("Warning: a section (index %d) already has a relocation table. Continuing...\n", tmp_index);
				else
					elf_head->sections[tmp_index]->relocatetable_index = &elf_head->sections[sec_index]->index;
			}
			/*
			tmp_index = elf_head->sections[sec_index]->sh_link;
			//sh_link has index (REL -> SYM)
			if (tmp_index >= 0 && tmp_index < elf_head->sectable_count) {
				IF_ELFPARSE_NOWRITETYPE(elf_head->sections[tmp_index])
					continue;
				if (elf_head->sections[sec_index]->symboltable_index != NULL)
					printf("Warning: the relocation section (index %d) already has a symbol table. Continuing...\n", sec_index);
				else
					elf_head->sections[sec_index]->symboltable_index = &elf_head->sections[tmp_index]->index;
			}
			*/
		}

	}

	elf_head->recompiled_size = 0;
	elf_head->map_list = NULL;

	return elf_head;
}

int getsectsize_withalign(elf_sechead_t* section) {
	int align_remain = section->sh_size % section->sh_addralign;
	return section->sh_size + (section->sh_addralign - align_remain);
}

int getsectsize_withpad(int f_index) {
	int mod;
	mod = f_index % ELFCOMPILE_DEFAULTPADDING;
	if (mod)
		return ELFCOMPILE_DEFAULTPADDING - mod;
	else
		return 0;
}


/******************************************************/
/* Note: free(index_array) must be called after usage */
/******************************************************/

int* getsectindexorder_offset(elf_head_t* elf_head) {
	int* index_array;
	elf_sechead_t** ptr_temp;
	int i;

	/*#######*/

	index_array = malloc(elf_head->sectable_count * sizeof(int));
	if (index_array == NULL)
		return terminate_error(ELIST_NOMEM);

	ptr_temp = malloc(elf_head->sectable_count * sizeof(elf_sechead_t*));
	if (ptr_temp == NULL)
		return terminate_error(ELIST_NOMEM);

	for (i = 0; i < elf_head->sectable_count; ++i)
		ptr_temp[i] = elf_head->sections[i];

	qsort(ptr_temp, elf_head->sectable_count, sizeof(elf_sechead_t*), esort_offset);

	for (i = 0; i < elf_head->sectable_count; ++i)
		index_array[i] = ptr_temp[i]->index;

	free(ptr_temp);
	return index_array;
}



void elf_expand(elf_head_t* elf_head, int section_index, int section_size) {

	/*#######*/

	elf_head->sections[section_index]->section_data = realloc(elf_head->sections[section_index]->section_data, section_size);
	if (elf_head->sections[section_index] == NULL)
		return terminate_error(ELIST_NOMEM);
	if (section_size > elf_head->sections[section_index]->sh_size)
		memset(elf_head->sections[section_index]->section_data + elf_head->sections[section_index]->sh_size, 0, section_size - elf_head->sections[section_index]->sh_size);

	elf_head->sections[section_index]->sh_size = section_size;

	elf_recalculate_offsets(elf_head);

	//elf_head->sections[section_index]->sh_size
	printf("TODO: Wii U RPX section LOUSER+0x4 modifications (textSize, dataSize). Is sdaBase important?");
	printf("Expanded section \"%s\".\n", elf_head->sections[section_index]->section_name);
}

void elf_shift(elf_head_t* elf_head, int section_index, int shift_amount) {

	int sec_index;
	int reloc_index;
	int symbol_index;
	int f_index;
	int symtable_index;

	int r_offset;
	int r_info;
	int r_addend;

	int st_value;

	byte r_type;
	int r_sym;

	int sym_offset;
	int val_temp;

	bool isrela;

	/*#######*/



	// find reallocatable addresses and shift them first

	for (sec_index = 0; sec_index < elf_head->sectable_count; ++sec_index) {

		if (elf_head->sections[sec_index]->relocatetable_index == NULL)
			continue;

		reloc_index = *elf_head->sections[sec_index]->relocatetable_index;

		IF_ELFPARSE_RELOCATETYPE(elf_head->sections[reloc_index]) {
		}
		else
			continue;

		symbol_index = elf_head->sections[reloc_index]->sh_link;
		if (elf_head->sections[symbol_index]->sh_type != ELFTYPE_SYMTAB) {
			if (!menumisc_display_ynsimple("The relocation table does not have a proper symbol table. Continue anyway?"))
				return terminate_error(ELIST_CONTINUE);
		}

		isrela = ELFPARSE_ISRELA(elf_head->sections[reloc_index]);

		for (f_index = 0; f_index < elf_head->sections[reloc_index]->sh_size; f_index += elf_head->sections[reloc_index]->sh_entsize) {



			r_offset = get32bit(elf_head->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, ehead_endian_convert(elf_head->endianness));
			r_info = get32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_INFO64 : ELFLOC_REL_INFO32), ehead_endian_convert(elf_head->endianness));
			r_addend = !isrela ? 0 : get32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), ehead_endian_convert(elf_head->endianness));

			r_type = r_info & 0xFF;
			r_sym = r_info >> 8;

			symtable_index = (elf_head->sections[symbol_index]->sh_entsize*r_sym);

			st_value = get32bit(elf_head->sections[symbol_index]->section_data, symtable_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SYM_VALUE64 : ELFLOC_SYM_VALUE32), ehead_endian_convert(elf_head->endianness));

			sym_offset = st_value + r_addend;

			// dest offset will be st_value + r_addend here
			if (sym_offset >= elf_head->sections[section_index]->sh_addr && sym_offset < elf_head->sections[section_index]->sh_addr + elf_head->sections[section_index]->sh_size) {
				set32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), (r_addend + shift_amount), ehead_endian_convert(elf_head->endianness));


				val_temp = get32bit(elf_head->sections[sec_index]->section_data, r_offset - elf_head->sections[sec_index]->sh_addr, true);
				switch (elf_head->processor) {
				case ELFPROC_PPC:
					// no relative address?
					val_temp = elf_relocparse_ppc(val_temp, r_type, 0, (r_addend + shift_amount), st_value, 0, ehead_endian_convert(elf_head->endianness));
					break;
				default:
					return terminate_error_hxno(ELIST_RELOC_UNKNOWNTYPE, elf_head->processor);
				}
				set32bit(elf_head->sections[sec_index]->section_data, r_offset - elf_head->sections[sec_index]->sh_addr, val_temp, true);

			}

			if (r_offset >= elf_head->sections[section_index]->sh_addr && r_offset < elf_head->sections[section_index]->sh_addr + elf_head->sections[section_index]->sh_size) {
				set32bit(elf_head->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, (r_offset + shift_amount), ehead_endian_convert(elf_head->endianness));
			}

		}


	}


	elf_head->sections[section_index]->sh_addr += shift_amount;
}

//addr_dst is either absolute virtual or index-based (i.e. based on the array index and not the PC offset)
void elf_inject(elf_head_t* elf_dst, elf_head_t* elf_src, inject_transfer_t** inject_array) {

	int i;
	//int* sect_baseaddr;
	int addr_dst;


	/*#######*/
	/*
	sect_baseaddr = malloc(sizeof(int)*elf_dst->sectable_count);
	memset(sect_baseaddr, -1, elf_dst->sectable_count);//BASEADDR_SECTIONARRAY_INVALID

	for (i = 0; eset == ELIST_SUCCESS && inject_array[i] != NULL; ++i) {

		if (!BASEADDR_SECTIONARRAY_INVALID(sect_baseaddr[inject_array[i]->sect_index_dest]) &&
			sect_baseaddr[inject_array[i]->sect_index_dest] != elf_dst->sections[inject_array[i]->sect_index_dest]->sh_addr &&
			!menumisc_display_ynsimple("Base address redefined. Continue?")) {
			terminate_error(ELIST_EXIT);
			break;
		}

		addr_dst = inject_array[i]->dest_addr;
		if (inject_array[i]->is_virtual)
			addr_dst -= elf_dst->sections[inject_array[i]->sect_index_dest]->sh_addr;

		sect_baseaddr[inject_array[i]->sect_index_dest] = elf_dst->sections[inject_array[i]->sect_index_dest]->sh_addr + addr_dst;//;//

	}
	*/



	for (i = 0; eset == ELIST_SUCCESS && inject_array[i] != NULL; ++i) {


		//CONVERT_VIRTTOINDEX_ADDRESS(inject_array[i]->is_virtual, inject_array[i]->dest_addr, elf_dst->sections[inject_array[i]->sect_index_dest]);



		//find relocation entries

		if (elf_src->sections[inject_array[i]->sect_index_source]->relocatetable_index != NULL) {
			elf_src->map_list = elf_dst->map_list;

			//, inject_array[i]->sect_index_source, , elf_dst->sections[inject_array[i]->sect_index_dest]->sh_addr + addr_dst
			elf_adjustrelocate_data(elf_src, inject_array, i);
			elf_src->map_list = NULL;

			if (eset&&eset != ELIST_CONTINUE)
				break;
		}

		addr_dst = inject_array[i]->dest_addr;
		if (inject_array[i]->is_virtual)
			addr_dst -= elf_dst->sections[inject_array[i]->sect_index_dest]->sh_addr;


		memcpy(elf_dst->sections[inject_array[i]->sect_index_dest]->section_data + addr_dst, elf_src->sections[inject_array[i]->sect_index_source]->section_data, elf_src->sections[inject_array[i]->sect_index_source]->sh_size);

		printf("Copied section \"%s\" to \"%s\".\n", elf_src->sections[inject_array[i]->sect_index_source]->section_name, elf_dst->sections[inject_array[i]->sect_index_dest]->section_name);
		printf(ELFPARSESTRING_INJECT_COPYRESULT"\n", elf_src->sections[inject_array[i]->sect_index_source]->sh_offset,
			elf_src->sections[inject_array[i]->sect_index_source]->sh_addr, elf_dst->sections[inject_array[i]->sect_index_dest]->sh_offset + addr_dst, elf_dst->sections[inject_array[i]->sect_index_dest]->sh_addr + addr_dst);

		// prepare relocation




	}



	// merge relocation tables

	elf_mergerelocate_data(elf_dst, elf_src, inject_array);




	//free(sect_baseaddr);


}

void elf_mergerelocate_data(elf_head_t* elf_dst, elf_head_t* elf_src, inject_transfer_t** inject_array) {
	int i;
	int j;
	rela_t** rela_sectlist;


	int f_index;
	rela_t* rela_item;
	rela_t* first_item;
	rela_t* last_item;
	rela_t* next_item;
	rela_t* dest_item;
	int reloc_index;

	int r_offset;
	int r_info;
	int r_addend;
	byte r_type;
	int r_sym;
	int symtable_index;
	int st_shndx;
	int symbol_index;
	int destsymbol_index;
	int st_value_dest;
	bool isrela;
	int tempbase;

	/*#######*/

	rela_sectlist = (rela_t**)malloc(sizeof(rela_t*)*elf_dst->sectable_count);
	memset(rela_sectlist, NULL, sizeof(rela_t*)*elf_dst->sectable_count);

	for (i = 0; eset == ELIST_SUCCESS && inject_array[i] != NULL; ++i) {
		if (rela_sectlist[inject_array[i]->sect_index_dest] == NULL &&
			elf_src->sections[inject_array[i]->sect_index_source]->relocatetable_index != NULL &&
			elf_dst->sections[inject_array[i]->sect_index_dest]->relocatetable_index != NULL
			) {

			reloc_index = *elf_dst->sections[inject_array[i]->sect_index_dest]->relocatetable_index;
			isrela = ELFPARSE_ISRELA(elf_dst->sections[reloc_index]);

			last_item = NULL;
			first_item = NULL;
			for (f_index = 0; f_index < elf_dst->sections[reloc_index]->sh_size; f_index += elf_dst->sections[reloc_index]->sh_entsize) {

				r_offset = get32bit(elf_dst->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, ehead_endian_convert(elf_dst->endianness));
				r_info = get32bit(elf_dst->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_dst->bit_size) ? ELFLOC_REL_INFO64 : ELFLOC_REL_INFO32), ehead_endian_convert(elf_dst->endianness));
				r_addend = !isrela ? 0 : get32bit(elf_dst->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_dst->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), ehead_endian_convert(elf_dst->endianness));


				rela_item = (rela_t*)calloc(sizeof(rela_t), 1);
				if (rela_item == NULL)
					return terminate_error(ELIST_NOMEM);

				rela_item->r_offset = r_offset;
				rela_item->r_info = r_info;
				rela_item->r_addend = r_addend;
				rela_item->next = NULL;

				if (first_item == NULL)
					first_item = rela_item;

				if (last_item != NULL)
					last_item->next = rela_item;

				last_item = rela_item;
			}

			rela_sectlist[inject_array[i]->sect_index_dest] = first_item;

		}
	}


	// remove old entries in destination table that are within the source section's range
	for (i = 0; eset == ELIST_SUCCESS && inject_array[i] != NULL; ++i) {
		if (elf_src->sections[inject_array[i]->sect_index_source]->relocatetable_index == NULL)
			continue;

		//reloc_index = *elf_src->sections[inject_array[i]->sect_index_source]->relocatetable_index;

		//if (rela_sectlist[inject_array[i]->sect_index_dest] == NULL)
			//continue;

		last_item = NULL;
		for (rela_item = rela_sectlist[inject_array[i]->sect_index_dest]; rela_item != NULL; rela_item = next_item) {
			next_item = rela_item->next;

			if (rela_item->r_offset >= inject_array[i]->dest_addr && rela_item->r_offset < (inject_array[i]->dest_addr + elf_src->sections[inject_array[i]->sect_index_source]->sh_size)) {

				if (next_item != NULL) {
					if (last_item == NULL) {
						// if first item in list
						rela_sectlist[inject_array[i]->sect_index_dest] = next_item;
					}
					else {
						last_item->next = next_item;
					}
				}
				else {
					if (last_item == NULL) {
						// if first item in list
						rela_sectlist[inject_array[i]->sect_index_dest] = NULL;
					}
					else {
						last_item->next = NULL;
					}
				}

				free(rela_item);
			}
			else {
				last_item = rela_item;
			}
		}
	}

	// place new relocation table inside old table
	for (i = 0; eset == ELIST_SUCCESS && inject_array[i] != NULL; ++i) {
		if (elf_src->sections[inject_array[i]->sect_index_source]->relocatetable_index == NULL)
			continue;

		reloc_index = *elf_src->sections[inject_array[i]->sect_index_source]->relocatetable_index;
		isrela = ELFPARSE_ISRELA(elf_src->sections[reloc_index]);

		symbol_index = elf_src->sections[reloc_index]->sh_link;
		if (elf_src->sections[symbol_index]->sh_type != ELFTYPE_SYMTAB) {
			if (!menumisc_display_ynsimple("The relocation table does not have a proper symbol table. Continue anyway?"))
				return terminate_error(ELIST_CONTINUE);
		}

		destsymbol_index = elf_dst->sections[*elf_dst->sections[inject_array[i]->sect_index_dest]->relocatetable_index]->sh_link;
		if (elf_dst->sections[destsymbol_index]->sh_type != ELFTYPE_SYMTAB) {
			if (!menumisc_display_ynsimple("The relocation table does not have a proper symbol table. Continue anyway?"))
				return terminate_error(ELIST_CONTINUE);
		}

		dest_item = rela_sectlist[inject_array[i]->sect_index_dest];
		for (f_index = 0; f_index < elf_src->sections[reloc_index]->sh_size; f_index += elf_src->sections[reloc_index]->sh_entsize) {


			r_offset = get32bit(elf_src->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, ehead_endian_convert(elf_src->endianness));
			r_info = get32bit(elf_src->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_src->bit_size) ? ELFLOC_REL_INFO64 : ELFLOC_REL_INFO32), ehead_endian_convert(elf_src->endianness));
			r_addend = !isrela ? 0 : get32bit(elf_src->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_src->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), ehead_endian_convert(elf_src->endianness));

			r_sym = r_info >> 8;
			r_type = r_info & 0xFF;

			symtable_index = (elf_src->sections[symbol_index]->sh_entsize*r_sym);

			st_shndx = get16bit(elf_src->sections[symbol_index]->section_data, symtable_index + (ehead_bitsize_convert(elf_src->bit_size) ? ELFLOC_SYM_NDX64 : ELFLOC_SYM_NDX32), ehead_endian_convert(elf_src->endianness));

			//TODO: reserved area?
			if (st_shndx == 0 || st_shndx >= 0xFF00)
				continue;

			// calculate new sym table value			

			///////
			//TODO: HACKISH
			///

			for (j = 0; inject_array[j] != NULL; ++j) {
				if (inject_array[j]->sect_index_source == st_shndx) {
					tempbase = inject_array[j]->dest_base;
					break;
				}
			}
			if (inject_array[j] == NULL)
				return terminate_error_no(ELIST_RELOC_SOURCENF, st_shndx);

			if (tempbase >= 0xC0000000) {
				return terminate_error(ELIST_RELOCMERGE_DESTSYMNOTFOUND);
			}
			else if (tempbase >= 0x10000000) {
				r_sym = 2; // $DATA
			}
			else if (tempbase >= 0x2000000) {
				r_sym = 1; // $TEXT
				r_addend += 0x20;
				//r_addend &= ~3;

				// not sure why this is the case
				if (r_type == R_PPC_REL24)
					continue;
			}

			///
			//HACKISH
			///////


			/*
			for (j = 0; j < elf_dst->sections[destsymbol_index]->sh_size; j += elf_dst->sections[destsymbol_index]->sh_entsize) {
				st_value_dest = get32bit(elf_dst->sections[destsymbol_index]->section_data, j + (ehead_bitsize_convert(elf_dst->bit_size) ? ELFLOC_SYM_VALUE64 : ELFLOC_SYM_VALUE32), ehead_endian_convert(elf_dst->endianness));
				if (st_value_dest == inject_array[i]->dest_base) {
					// found.
					break;
				}
			}

			if (j >= elf_dst->sections[destsymbol_index]->sh_size) {
				return terminate_error(ELIST_RELOCMERGE_DESTSYMNOTFOUND);
			}
			*/

			r_info = (r_sym << 8) | r_type;

			rela_item = (rela_t*)calloc(sizeof(rela_t), 1);
			if (rela_item == NULL)
				return terminate_error(ELIST_NOMEM);

			rela_item->r_offset = r_offset;
			rela_item->r_info = r_info;
			rela_item->r_addend = r_addend;
			rela_item->next = NULL;

			for (; dest_item != NULL; dest_item = next_item) {
				next_item = dest_item->next;
				if (next_item == NULL || next_item->r_offset >= rela_item->r_offset) {
					break;
				}
			}


			if (dest_item != NULL) {
				next_item = dest_item->next;
				dest_item->next = rela_item;
				rela_item->next = next_item;
				dest_item = rela_item;
			}
		}
	}

	// apply the tables
	for (i = 0; i < elf_dst->sectable_count; ++i) {

		if (rela_sectlist[i] == NULL)
			continue;

		reloc_index = *elf_dst->sections[i]->relocatetable_index;
		isrela = ELFPARSE_ISRELA(elf_dst->sections[reloc_index]);

		// clear old data
		free(elf_dst->sections[reloc_index]->section_data);

		//get count
		for (j = 0, rela_item = rela_sectlist[i]; rela_item != NULL; rela_item = rela_item->next, ++j) {
		}

		// allocate new size
		elf_dst->sections[reloc_index]->sh_size = j * elf_dst->sections[reloc_index]->sh_entsize;
		elf_dst->sections[reloc_index]->section_data = (byte*)malloc(elf_dst->sections[reloc_index]->sh_size);

		for (f_index = 0, rela_item = rela_sectlist[i]; rela_item != NULL; rela_item = next_item, f_index += elf_dst->sections[reloc_index]->sh_entsize) {

			next_item = rela_item->next;
			set32bit(elf_dst->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, rela_item->r_offset, ehead_endian_convert(elf_dst->endianness));
			set32bit(elf_dst->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_dst->bit_size) ? ELFLOC_REL_INFO64 : ELFLOC_REL_INFO32), rela_item->r_info, ehead_endian_convert(elf_dst->endianness));
			if (isrela)
				set32bit(elf_dst->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_dst->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), rela_item->r_addend, ehead_endian_convert(elf_dst->endianness));

			free(rela_item);
		}
	}
	free(rela_sectlist);
}

void elf_patch(elf_head_t* elf_dst, byte* bin_src, int sect_dst, int addr_dst, int src_size, bool addr_dst_isvirtual) {
	CONVERT_VIRTTOINDEX_ADDRESS(addr_dst_isvirtual, addr_dst, elf_dst->sections[sect_dst]);

	memcpy(elf_dst->sections[sect_dst]->section_data + addr_dst, bin_src, src_size);
	printf("Patched binary to \"%s\".\n", elf_dst->sections[sect_dst]->section_name);
	printf(ELFPARSESTRING_PATCH_COPYRESULT"\n", elf_dst->sections[sect_dst]->sh_offset + addr_dst, elf_dst->sections[sect_dst]->sh_addr + addr_dst);
}

void elf_adjustrelocate_data(elf_head_t* elf_head, inject_transfer_t** inject_array, int inject_index) {

	int f_index;
	int r_offset;
	int r_info;
	int r_addend;
	byte r_type;
	int r_sym;
	int st_value;
	int st_shndx;
	int st_name;
	int addr_temp;
	bool isrela;

	int i;
	int map_count;

	int addrset_from;
	int addrset_to;
	int addrset_tobase;
	int reloc_index;

	int symbol_index;
	int string_index;
	int sourcesec_index;
	int sourcedest_index;

	int symtable_index;
	char* sym_name;

	/*#######*/

	sourcesec_index = inject_array[inject_index]->sect_index_source;
	sourcedest_index = inject_array[inject_index]->sect_index_dest;
	reloc_index = *elf_head->sections[sourcesec_index]->relocatetable_index;

	IF_ELFPARSE_RELOCATETYPE(elf_head->sections[reloc_index]);
	else
		return terminate_error(ELIST_EXIT);


		symbol_index = elf_head->sections[reloc_index]->sh_link;
		if (elf_head->sections[symbol_index]->sh_type != ELFTYPE_SYMTAB) {
			if (!menumisc_display_ynsimple("The relocation table does not have a proper symbol table. Continue anyway?"))
				return terminate_error(ELIST_CONTINUE);
		}

		string_index = elf_head->sections[symbol_index]->sh_link;
		if (elf_head->sections[string_index]->sh_type != ELFTYPE_STRTAB) {
			if (!menumisc_display_ynsimple("The symbol table does not have a proper string table. Continue anyway?"))
				return terminate_error(ELIST_CONTINUE);
		}


		isrela = ELFPARSE_ISRELA(elf_head->sections[reloc_index]);

		for (f_index = 0; f_index < elf_head->sections[reloc_index]->sh_size; f_index += elf_head->sections[reloc_index]->sh_entsize) {
			r_offset = get32bit(elf_head->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, ehead_endian_convert(elf_head->endianness));
			r_info = get32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_INFO64 : ELFLOC_REL_INFO32), ehead_endian_convert(elf_head->endianness));
			r_addend = !isrela ? 0 : get32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), ehead_endian_convert(elf_head->endianness));

			r_type = r_info & 0xFF;
			r_sym = r_info >> 8;

			symtable_index = (elf_head->sections[symbol_index]->sh_entsize*r_sym);

			st_name = get32bit(elf_head->sections[symbol_index]->section_data, symtable_index + ELFLOC_SYM_NAME, ehead_endian_convert(elf_head->endianness));
			st_value = get32bit(elf_head->sections[symbol_index]->section_data, symtable_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SYM_VALUE64 : ELFLOC_SYM_VALUE32), ehead_endian_convert(elf_head->endianness));
			st_shndx = get16bit(elf_head->sections[symbol_index]->section_data, symtable_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SYM_NDX64 : ELFLOC_SYM_NDX32), ehead_endian_convert(elf_head->endianness));

			/*
			if (st_shndx == index) {
				// testing if inside same section (i.e. calls to functions inside same section)

			}
			else {
				// testing if inside different section
				printf("TODO: support different sections\n");
				continue;
			}
			*/

			addrset_from = inject_array[inject_index]->dest_addr;
			addrset_from += r_offset;

			if (st_shndx == 0) {
				// testing if an external variable (has value SHN_UNDEF)			

				sym_name = elf_head->sections[string_index]->section_data + st_name;
				sym_name = demangle_name(sym_name, CUSE_GCC);//temp
				if (sym_name == NULL)
					return terminate_error(ELIST_NM_FAILED);

				if (eset)
					return;

				if (elf_head->map_list == NULL) {
					printf("Map file not imported. Skipping relocation for \"%s\"...\n", sym_name);
					continue;
				}

				map_count = map_getcount(elf_head->map_list);

				for (i = 0; i < map_count; ++i) {
					if (!strcmp(elf_head->map_list[i]->map_name, sym_name))
						break;
				}

				if (i < map_count)
					addrset_to = elf_head->map_list[i]->map_value;
				else
					terminate_error_str(ELIST_NM_MAPVALNOTFOUND, sym_name);

				free(sym_name);

				if (eset)
					return;

				st_value = 0;
				r_addend = 0;
			}
			else if (st_shndx >= 0xFF00) {
				// testing if in reserve area (SHN_LORESERVE - SHN_HIRESERVE)
				printf("TODO: support indices above SHN_LORESERVE\n");
				continue;
			}
			else {

				for (i = 0; inject_array[i] != NULL; ++i) {
					if (inject_array[i]->sect_index_source == st_shndx) {
						addrset_to = inject_array[i]->dest_addr;
						addrset_tobase = inject_array[i]->dest_base;
						break;
					}
				}

				if (inject_array[i] == NULL)
					return terminate_error_no(ELIST_RELOC_SOURCENF, st_shndx);

			}



			addrset_to += r_addend;
			addrset_to += st_value;


			addr_temp = get32bit(elf_head->sections[sourcesec_index]->section_data, r_offset, true);
			switch (elf_head->processor) {
			case ELFPROC_PPC:
				addr_temp = elf_relocparse_ppc(addr_temp, r_type, addrset_to, addrset_from, ehead_endian_convert(elf_head->endianness));
				break;
			default:
				return terminate_error_hxno(ELIST_RELOC_UNKNOWNTYPE, elf_head->processor);
			}

			if (eset)
				return;

			set32bit(elf_head->sections[sourcesec_index]->section_data, r_offset, addr_temp, true);

			if (st_shndx != 0) {
				set32bit(elf_head->sections[reloc_index]->section_data, f_index + ELFLOC_REL_OFFSET, addrset_from, ehead_endian_convert(elf_head->endianness));
				//?
				//set32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_INFO64 : ELFLOC_REL_INFO32), (sourcedest_index << 8) | (r_type), ehead_endian_convert(elf_head->endianness));
				if (isrela)
					set32bit(elf_head->sections[reloc_index]->section_data, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_REL_ADDEND64 : ELFLOC_REL_ADDEND32), addrset_to - addrset_tobase, ehead_endian_convert(elf_head->endianness));
			}

		}

}



//free must be called afterwards
char* demangle_name(char* input, enum COMPILER_USE cuse) {
	char* output;
	size_t out_i;
	size_t out_size;

	size_t in_i;

	/*#######*/


	out_i = 0;
	out_size = 0;
	in_i = 0;

	switch (cuse) {
	case CUSE_GCC:

		if (input[in_i] == '_'&&input[in_i + 1] == MANGLETYPE_GCC_BEGIN) {

			//mangled name



			//demangle.h


			output = cplus_demangle_v3(input, DMGL_PARAMS | DMGL_ANSI);






			/*
			for (in_i = 2;input[in_i];++in_i) {

			}

			in_i += 2;

			while (input[in_i]) {


			}


			if (!is_numchar(input[in_i])) {
				switch (input[in_i]) {
				case MANGLETYPE_GCC_NAMESPACE:

					break;
				default:
					return terminate_error(ELIST_NM_UNKNOWNTYPE);
				}

				while (out_i >= out_size) {
					out_size += CHARBUFF_SMALL;
					output = realloc(output, out_size);
					if (output == NULL)
						return terminate_error(ELIST_NOMEM);
				}
			}
			*/

		}
		else {
			//normal name
			output = malloc(strlen(input) + 1);
			if (output == NULL)
				return terminate_error(ELIST_NOMEM);
			strcpy(output, input);
		}







		break;
	default:
		return terminate_error(ELIST_NM_UNKNOWNCOMPILER);
		break;
	}

	return output;
}



int elf_relocparse_ppc(int addr_temp, byte r_type, int new_basevirtaddr, int relativeaddr, bool be) {

	uint32_t set_val;

	/*#######*/

	set_val = new_basevirtaddr;	
	if (!be)
		set_val = swapendian(set_val);

	switch (r_type) {
	case R_PPC_ADDR32:
		addr_temp = set_val;
		break;
	case R_PPC_ADDR16_LO:
		addr_temp &= 0xFFFF;
		set_val &= 0xFFFF;
		set_val <<= 16;
		addr_temp |= set_val;
		break;
	case R_PPC_ADDR16_HI:
		addr_temp &= 0xFFFF;
		set_val &= ~0xFFFF;
		addr_temp |= set_val;
		break;
	case R_PPC_ADDR16_HA:
		addr_temp &= 0xFFFF;
		if (!be) {
			if (set_val & 0x80000000)
				set_val++;
		}
		else {
			if (set_val & 0x8000)
				set_val += 0x10000;
		}
		set_val &= ~0xFFFF;
		addr_temp |= set_val;
		break;
	case R_PPC_REL24:
		if (!be)
			set_val = swapendian(set_val);
		set_val -= relativeaddr;
		if (!be)
			set_val = swapendian(set_val);

		addr_temp &= ~0x3FFFFFC;
		set_val += (addr_temp & 0x3FFFFFC);
		set_val &= 0x3FFFFFC;
		addr_temp |= set_val;
		break;
	default:
		addr_temp = -1;
		terminate_error_hxno(ELIST_RELOC_UNKNOWNCOMMAND, r_type);
	}
	return addr_temp;
}

int esort_offset(const void* a, const void* b) {
	const elf_sechead_t **left = (const elf_sechead_t **)a;
	const elf_sechead_t **right = (const elf_sechead_t **)b;

	return ((**right).sh_offset < (**left).sh_offset) - ((**left).sh_offset < (**right).sh_offset);
	//return ((elf_sechead_t**)a)->sh_offset - ((elf_sechead_t**)b)->sh_offset;
}

void elf_recalculate_offsets(elf_head_t* elf_head) {

	int i;
	int* index_array;

	int f_index;

	/*#######*/

	index_array = getsectindexorder_offset(elf_head);
	if (eset)
		return;

	f_index = elf_head->sectable_offset + (elf_head->sectable_count*elf_head->sectable_size);

	for (i = 0; i < elf_head->sectable_count; ++i) {
		IF_ELFPARSE_NOWRITETYPE(elf_head->sections[index_array[i]])
			continue;
		elf_head->sections[index_array[i]]->sh_offset = f_index;
		f_index += elf_head->sections[index_array[i]]->sh_size;
		f_index += getsectsize_withpad(f_index);
	}

	free(index_array);
	elf_head->recompiled_size = f_index;
}



void elf_save(elf_head_t* elf_head) {

	int i;
	byte* file_write;
	int f_index;
	FILE* output_file;

	/*#######*/

	if (!elf_head->recompiled_size) {
		elf_recalculate_offsets(elf_head);
		if (eset)
			return;
	}


	file_write = malloc(elf_head->recompiled_size);
	if (file_write == NULL)
		return terminate_error(ELIST_NOMEM);
	memset(file_write, 0, elf_head->recompiled_size);
	memcpy(file_write, elf_head->header_data, elf_head->head_size);

	f_index = elf_head->sectable_offset;
	for (i = 0; i < elf_head->sectable_count; ++i) {
		set32bit(file_write, f_index + ELFLOC_SEC_NAME, elf_head->sections[i]->sh_name, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + ELFLOC_SEC_TYPE, elf_head->sections[i]->sh_type, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + ELFLOC_SEC_ATTR, elf_head->sections[i]->sh_flags, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_VADDR64 : ELFLOC_SEC_VADDR32), elf_head->sections[i]->sh_addr, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_OFFSET64 : ELFLOC_SEC_OFFSET32), elf_head->sections[i]->sh_offset, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_SIZE64 : ELFLOC_SEC_SIZE32), elf_head->sections[i]->sh_size, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_LINK64 : ELFLOC_SEC_LINK32), elf_head->sections[i]->sh_link, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_INFO64 : ELFLOC_SEC_INFO32), elf_head->sections[i]->sh_info, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_ALIGN64 : ELFLOC_SEC_ALIGN32), elf_head->sections[i]->sh_addralign, ehead_endian_convert(elf_head->endianness));
		set32bit(file_write, f_index + (ehead_bitsize_convert(elf_head->bit_size) ? ELFLOC_SEC_ENT64 : ELFLOC_SEC_ENT32), elf_head->sections[i]->sh_entsize, ehead_endian_convert(elf_head->endianness));
		f_index += elf_head->sectable_size;

		IF_ELFPARSE_NOWRITETYPE(elf_head->sections[i])
			continue;
		memcpy(file_write + elf_head->sections[i]->sh_offset, elf_head->sections[i]->section_data, elf_head->sections[i]->sh_size);
	}

	output_file = fopen(elf_head->filename, "wb");
	if (output_file == NULL)
		return terminate_error(ELIST_FILECANNOTOPENOUT);
	fwrite(file_write, sizeof(byte), elf_head->recompiled_size, output_file);
	fclose(output_file);
	free(file_write);

	printf("ELF saved successfully.\n");
	elf_head->recompiled_size = 0;
}

void map_load(map_item*** map_refarray, char* fileuse) {
	size_t map_array_size;
	FILE* input_file;

	/*#######*/

	//reading file

	input_file = fopen(fileuse, "r+");
	if (input_file == NULL)
		return terminate_error(ELIST_FILECANNOTOPEN);

	if (*map_refarray != NULL)
		map_unload(map_refarray);

	map_array_size = 0;
	FUNC_RESIZEMAP((*map_refarray), map_array_size);

	map_add(map_refarray, map_array_size, input_file);
	if (!eset)
		printf("Symbol map file \"%s\" loaded successfully.\n", fileuse);

	fclose(input_file);
}

void map_unload(map_item*** map_refarray) {
	size_t map_array_size;
	size_t i;

	/*#######*/

	map_array_size = map_getcount(*map_refarray);
	for (i = 0; i < map_array_size; i++) {
		free((*map_refarray)[i]->map_name);
		free((*map_refarray)[i]);
	}
	free((*map_refarray));
	(*map_refarray) = NULL;
}

size_t map_getcount(map_item** map_refarray) {
	size_t count;

	/*#######*/

	for (count = 0; map_refarray[count] != NULL; count++);
	return count;
}

void map_add(map_item*** map_refarray, size_t map_array_size, FILE* input_file) {

	size_t l_index;
	int mitem_read_ws;
	map_item* mitem_temp;
	size_t size_set;
	char* line_buffer;
	char chinput;

	/*#######*/

	mitem_temp = NULL;

	for (mitem_read_ws = 0, eset = ELIST_SUCCESS, FUNC_INITLINEBUFFER(line_buffer, size_set, l_index); eset == ELIST_SUCCESS;) {
		while (l_index >= size_set) {
			size_set += MENU_MAXCHAR;
			line_buffer = realloc(line_buffer, size_set);
			if (line_buffer == NULL)
				return terminate_error(ELIST_NOMEM);
		}
		line_buffer[l_index] = '\0';

		chinput = getc(input_file);
		if (chinput == EOF || chinput == '\n') {
			if (mitem_read_ws) {
				mitem_read_ws = 0;
				if (!strcmp(MAPVALUE_FREESPACE_IDENTIFIER, line_buffer)) {
					mitem_temp->map_value = MAPVALUE_FREESPACE_VALUE;
				}
				else {
					mitem_temp->map_value = (uint32_t)strtoul(line_buffer, NULL, 0);
				}


				(*map_refarray)[map_array_size++] = mitem_temp;
				FUNC_RESIZEMAP((*map_refarray), map_array_size);
				FUNC_INITLINEBUFFER(line_buffer, size_set, l_index);
				mitem_temp = NULL;
			}
			else {
				eset = ELIST_FILEMAP_VALNOTSPECIFIED;
				continue;
			}
			if (chinput == EOF)
				break;
		}
		else if (isspace(chinput)) {

			if (!mitem_read_ws) {

				mitem_temp = malloc(sizeof(map_item));
				mitem_temp->map_name = line_buffer;
				mitem_temp->map_value = 0;

				FUNC_INITLINEBUFFER(line_buffer, size_set, l_index);

			}

			mitem_read_ws++;
			do {
				chinput = getc(input_file);
			} while (!(chinput == '\n' || chinput == EOF) && isspace(chinput));
			ungetc(chinput, input_file);
		}
		else {
			if (mitem_read_ws >= 2) {
				eset = ELIST_FILEMAP_TOOMANYARGUMENTS;
				continue;
			}

			if (!mitem_read_ws) {
				//reading symbol name
				if (chinput == '\\') {
					chinput = getc(input_file);
					switch (chinput) {
					case EOF:
						eset = ELIST_FILEMAP_VALNOTSYMBOL;
						continue;
					default:
						break;
					}
				}
				if (l_index == 0 && is_numchar(chinput)) {
					eset = ELIST_FILEMAP_VALNOTSYMBOL;
					continue;
				}
			}
			else {
				//reading value
				if (!is_numchar(chinput) && l_index != 1 && chinput != 'x'&& line_buffer[0] != '0' && !is_freespaceid(chinput, l_index)) {
					eset = ELIST_FILEMAP_VALNOTNUMBER;
					continue;
				}
			}

			line_buffer[l_index++] = chinput;
		}
	}
	if (eset)
		return terminate_error(eset);

}
