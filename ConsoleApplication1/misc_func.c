#include "misc_func.h"

#include <string.h>
#include "elf_parse.h"

int get16bit(byte* buffer, size_t index, int be) {
	if (be)
		return (buffer[index + 1]) | (buffer[index] << 8);
	else
		return buffer[index] | (buffer[index + 1] << 8);
}

int get32bit(byte* buffer, size_t index, int be) {
	if (be)
		return buffer[index + 3] | (buffer[index + 2] << 8) | (buffer[index + 1] << 16) | (buffer[index] << 24);
	else
		return buffer[index] | (buffer[index + 1] << 8) | (buffer[index + 2] << 16) | (buffer[index + 3] << 24);
}

void set32bit(byte* buffer, size_t index, int val, int be) {
	if (be) {
		buffer[index + 0] = (val >> 24) & 0xFF;
		buffer[index + 1] = (val >> 16) & 0xFF;
		buffer[index + 2] = (val >> 8) & 0xFF;
		buffer[index + 3] = (val >> 0) & 0xFF;
	}
	else {
		buffer[index + 0] = (val >> 0) & 0xFF;
		buffer[index + 1] = (val >> 8) & 0xFF;
		buffer[index + 2] = (val >> 16) & 0xFF;
		buffer[index + 3] = (val >> 24) & 0xFF;
	}
}

uint32_t swapendian(uint32_t source) {
	return ((source & 0xFF000000) >> 24) | ((source & 0xFF0000) >> 8) | ((source & 0xFF00) << 8) | ((source & 0xFF) << 24);
}

int is_numchar(char c) {
	return (c >= '0'&&c <= '9');
}

int is_freespaceid(char c, int l_index) {
	if (l_index >= strlen(MAPVALUE_FREESPACE_IDENTIFIER))
		return false;
	
	return MAPVALUE_FREESPACE_IDENTIFIER[l_index] == c;
}