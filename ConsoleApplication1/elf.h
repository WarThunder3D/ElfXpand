
#ifndef DEF_ELF
#define DEF_ELF

#define ELFLOC_HEAD_MAGIC 0x0
#define ELFLOC_HEAD_BITSIZE 0x4
#define ELFLOC_HEAD_ENDIANNESS 0x5
#define ELFLOC_HEAD_PROCESSOR 0x12
#define ELFLOC_HEAD_TABLE_PG_O32 0x1C
#define ELFLOC_HEAD_TABLE_PG_O64 0x20
#define ELFLOC_HEAD_TABLE_SEC_O32 0x20
#define ELFLOC_HEAD_TABLE_SEC_O64 0x28
#define ELFLOC_HEAD_SIZE32 0x28
#define ELFLOC_HEAD_SIZE64 0x34
#define ELFLOC_HEAD_TABLE_SEC_S32 0x2E
#define ELFLOC_HEAD_TABLE_SEC_S64 0x3A	
#define ELFLOC_HEAD_TABLE_SEC_C32 0x30
#define ELFLOC_HEAD_TABLE_SEC_C64 0x3C
#define ELFLOC_HEAD_TABLE_SEC_N32 0x32
#define ELFLOC_HEAD_TABLE_SEC_N64 0x3E

#define ELFLOC_SEC_NAME 0x0
#define ELFLOC_SEC_TYPE 0x4
#define ELFLOC_SEC_ATTR 0x8
#define ELFLOC_SEC_VADDR32 0xC
#define ELFLOC_SEC_VADDR64 0x10
#define ELFLOC_SEC_OFFSET32 0x10
#define ELFLOC_SEC_OFFSET64 0x18
#define ELFLOC_SEC_SIZE32 0x14
#define ELFLOC_SEC_SIZE64 0x20
#define ELFLOC_SEC_LINK32 0x18
#define ELFLOC_SEC_LINK64 0x28
#define ELFLOC_SEC_INFO32 0x1C
#define ELFLOC_SEC_INFO64 0x2C
#define ELFLOC_SEC_ALIGN32 0x20
#define ELFLOC_SEC_ALIGN64 0x30
#define ELFLOC_SEC_ENT32 0x24
#define ELFLOC_SEC_ENT64 0x38

#define ELFLOC_REL_OFFSET 0x0
#define ELFLOC_REL_INFO32 0x4
#define ELFLOC_REL_INFO64 0x8
#define ELFLOC_REL_ADDEND32 0x8
#define ELFLOC_REL_ADDEND64 0x10

#define ELFLOC_SYM_NAME 0x0
#define ELFLOC_SYM_VALUE32 0x4
#define ELFLOC_SYM_VALUE64 0x8
#define ELFLOC_SYM_NDX32 0xE
#define ELFLOC_SYM_NDX64 0x6

#define ELFPROC_PPC 0x14
#define ELFPROC_PPC64 0x15

#define ELFTYPE_NULL 0x0
#define ELFTYPE_SYMTAB 0x2
#define ELFTYPE_STRTAB 0x3
#define ELFTYPE_RELA 0x4
#define ELFTYPE_NOBITS 0x8
#define ELFTYPE_REL 0x9

//#define ELFSIZE_REL 0x8
//#define ELFSIZE_RELA 0xC

#define ELFCOMPILE_DEFAULTPADDING 0x40 // Wii U RPX needs this padding value


/* PowerPC relocations defined by the ABIs */
#define R_PPC_NONE 0x0
#define R_PPC_ADDR32 0x1   /* 32bit absolute address */
#define R_PPC_ADDR24 0x2   /* 26bit address, 2 bits ignored.  */
#define R_PPC_ADDR16 0x3   /* 16bit absolute address */
#define R_PPC_ADDR16_LO 0x4   /* lower 16bit of absolute address */
#define R_PPC_ADDR16_HI 0x5   /* high 16bit of absolute address */
#define R_PPC_ADDR16_HA 0x6   /* adjusted high 16bit */
#define R_PPC_ADDR14 0x7   /* 16bit address, 2 bits ignored */
#define R_PPC_ADDR14_BRTAKEN 0x8
#define R_PPC_ADDR14_BRNTAKEN 0x9
#define R_PPC_REL24 0xA  /* PC relative 26 bit */
#define R_PPC_REL14 0xB  /* PC relative 16 bit */
#define R_PPC_REL14_BRTAKEN 0xC
#define R_PPC_REL14_BRNTAKEN 0xD
#define R_PPC_GOT16 0xE
#define R_PPC_GOT16_LO 0xF
#define R_PPC_GOT16_HI 0x10
#define R_PPC_GOT16_HA 0x11
#define R_PPC_PLTREL24 0x12
#define R_PPC_COPY 0x13
#define R_PPC_GLOB_DAT 0x14
#define R_PPC_JMP_SLOT 0x15
#define R_PPC_RELATIVE 0x16
#define R_PPC_LOCAL24PC 0x17
#define R_PPC_UADDR32 0x18
#define R_PPC_UADDR16 0x19
#define R_PPC_REL32 0x1A
#define R_PPC_PLT32 0x1B
#define R_PPC_PLTREL32 0x1C
#define R_PPC_PLT16_LO 0x1D
#define R_PPC_PLT16_HI 0x1E
#define R_PPC_PLT16_HA 0x1F
#define R_PPC_SDAREL16 0x20
#define R_PPC_SECTOFF 0x21
#define R_PPC_SECTOFF_LO 0x22
#define R_PPC_SECTOFF_HI 0x23
#define R_PPC_SECTOFF_HA 0x24

#define SHN_UNDEF = 0;

#endif