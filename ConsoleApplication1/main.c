

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "errorhandler.h"
#include "types.h"
#include "menu_func.h"
#include "elf_parse.h"



int main(int argc, char** argv)
{

	int arg_index;
	struct headflags_s headflags = { .menu_immediate_operation = MENUIMMOP_NONE,.mapfile = NULL };
	char* filename = NULL;

	elf_head_t* elf_main;

	/*#######*/

	if (argc < 2) {
		filename = menumisc_getfilename(MENUSTRING_OPEN_S1_READELF);
		if (eset)
			exit(eset);
		//terminate_error(ELIST_NOARGUMENTS, true);
	}
	else {
		for (arg_index = 1; arg_index < argc; ++arg_index) {
			if (argv[arg_index][0] == '-') {
				switch (argv[arg_index][1]) {
				case MENUOP_MAP:
					if (++arg_index >= argc) {
						terminate_error(ELIST_LOAD_MAP_BADARGUMENT);
						exit(eset);
					}
					headflags.mapfile = argv[arg_index];
					break;
				case MENUOP_INJECT:
					if (headflags.menu_immediate_operation != MENUIMMOP_NONE) {
						terminate_error(ELIST_INIT_IMMEDIATEOPERATIONSPECIFIED);
						exit(eset);
					}

					if (((++arg_index) + 1) >= argc) {
						terminate_error(ELIST_INIT_INJECT_NOTENOUGHARGS);
						exit(eset);
					}

					headflags.immediateop_params.inject.source_object_file = argv[arg_index++];
					headflags.immediateop_params.inject.section_map_file = argv[arg_index];

					headflags.menu_immediate_operation = MENUIMMOP_INJECT;
					break;
				default:
					terminate_error(ELIST_BADARGUMENT);
					exit(eset);
				}
			}
			else {// if (arg_index == argc - 1) {
				if (filename != NULL) {
					terminate_error(ELIST_FILEGIVEN);
					exit(eset);
				}
				filename = argv[arg_index];
			}

			//printf("%s\n", argv[arg_index]);
		}
	}


	if (filename == NULL) {
		terminate_error(ELIST_NOFILENAME);
		exit(eset);
	}

	elf_main = load_elf(filename);
	if (!eset) {
		if (headflags.mapfile != NULL) {
			map_load(&elf_main->map_list, headflags.mapfile);
			if (eset)
				exit(eset);
		}

		switch (headflags.menu_immediate_operation) {
		case MENUIMMOP_INJECT:
			operation_inject(elf_main, headflags.immediateop_params.inject.source_object_file, headflags.immediateop_params.inject.section_map_file);
			if (eset)
				exit(eset);
			break;
		default:
			menu_main(elf_main);
			break;
		}


	}

	return 0;
}

