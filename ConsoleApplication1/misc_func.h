#ifndef DEF_MISC_FUNC
#define DEF_MISC_FUNC

#include "types.h"

int get16bit(byte* buffer, size_t index, int be);
int get32bit(byte* buffer, size_t index, int be);
void set32bit(byte* buffer, size_t index, int val, int be);
uint32_t swapendian(uint32_t source);
int is_numchar(char c);
int is_freespaceid(char c, int l_index);

#endif