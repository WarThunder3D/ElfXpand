#include "errorhandler.h"



void* terminate_error(enum ERROR_LIST error) {
	eset = error;
	printf("Error: %s Error code: %d\n", ERROR_LIST_STRINGS[error], error);
	return NULL;
}

void* terminate_error_no(enum ERROR_LIST error, int no) {
	eset = error;
	printf("Error: %s (%d) Error code: %d\n", ERROR_LIST_STRINGS[error], no, error);
	return NULL;
}

void* terminate_error_hxno(enum ERROR_LIST error, int no) {
	eset = error;
	printf("Error: %s (0x%X) Error code: %d\n", ERROR_LIST_STRINGS[error], no, error);
	return NULL;
}

void* terminate_error_str(enum ERROR_LIST error, char* st) {
	eset = error;
	printf("Error: %s \"%s\" Error code: %d\n", ERROR_LIST_STRINGS[error], st, error);
	return NULL;
}