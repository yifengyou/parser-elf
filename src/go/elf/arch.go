// Package elf : arch.go implements architecture specific relocation types
package elf

// Relocation types for x86-64.
type R_X86_64 int

const (
	R_X86_64_NONE            R_X86_64 = 0  // No relocation.
	R_X86_64_64              R_X86_64 = 1  // Add 64 bit symbol value.
	R_X86_64_PC32            R_X86_64 = 2  // PC-relative 32 bit signed sym value.
	R_X86_64_GOT32           R_X86_64 = 3  // PC-relative 32 bit GOT offset.
	R_X86_64_PLT32           R_X86_64 = 4  // PC-relative 32 bit PLT offset.
	R_X86_64_COPY            R_X86_64 = 5  // Copy data from shared object.
	R_X86_64_GLOB_DAT        R_X86_64 = 6  // Set GOT entry to data address.
	R_X86_64_JMP_SLOT        R_X86_64 = 7  // Set GOT entry to code address.
	R_X86_64_RELATIVE        R_X86_64 = 8  // Add load address of shared object.
	R_X86_64_GOTPCREL        R_X86_64 = 9  // Add 32 bit signed pcrel offset to GOT.
	R_X86_64_32              R_X86_64 = 10 // Add 32 bit zero extended symbol value
	R_X86_64_32S             R_X86_64 = 11 // Add 32 bit sign extended symbol value
	R_X86_64_16              R_X86_64 = 12 // Add 16 bit zero extended symbol value
	R_X86_64_PC16            R_X86_64 = 13 // Add 16 bit signed extended pc relative symbol value
	R_X86_64_8               R_X86_64 = 14 // Add 8 bit zero extended symbol value
	R_X86_64_PC8             R_X86_64 = 15 // Add 8 bit signed extended pc relative symbol value
	R_X86_64_DTPMOD64        R_X86_64 = 16 // ID of module containing symbol
	R_X86_64_DTPOFF64        R_X86_64 = 17 // Offset in TLS block
	R_X86_64_TPOFF64         R_X86_64 = 18 // Offset in static TLS block
	R_X86_64_TLSGD           R_X86_64 = 19 // PC relative offset to GD GOT entry
	R_X86_64_TLSLD           R_X86_64 = 20 // PC relative offset to LD GOT entry
	R_X86_64_DTPOFF32        R_X86_64 = 21 // Offset in TLS block
	R_X86_64_GOTTPOFF        R_X86_64 = 22 // PC relative offset to IE GOT entry
	R_X86_64_TPOFF32         R_X86_64 = 23 // Offset in static TLS block
	R_X86_64_PC64            R_X86_64 = 24 // PC relative 64-bit sign extended symbol value.
	R_X86_64_GOTOFF64        R_X86_64 = 25
	R_X86_64_GOTPC32         R_X86_64 = 26
	R_X86_64_GOT64           R_X86_64 = 27
	R_X86_64_GOTPCREL64      R_X86_64 = 28
	R_X86_64_GOTPC64         R_X86_64 = 29
	R_X86_64_GOTPLT64        R_X86_64 = 30
	R_X86_64_PLTOFF64        R_X86_64 = 31
	R_X86_64_SIZE32          R_X86_64 = 32
	R_X86_64_SIZE64          R_X86_64 = 33
	R_X86_64_GOTPC32_TLSDESC R_X86_64 = 34
	R_X86_64_TLSDESC_CALL    R_X86_64 = 35
	R_X86_64_TLSDESC         R_X86_64 = 36
	R_X86_64_IRELATIVE       R_X86_64 = 37
	R_X86_64_RELATIVE64      R_X86_64 = 38
	R_X86_64_PC32_BND        R_X86_64 = 39
	R_X86_64_PLT32_BND       R_X86_64 = 40
	R_X86_64_GOTPCRELX       R_X86_64 = 41
	R_X86_64_REX_GOTPCRELX   R_X86_64 = 42
)

var rx86_64Strings = []flagName{
	{0, "R_X86_64_NONE"},
	{1, "R_X86_64_64"},
	{2, "R_X86_64_PC32"},
	{3, "R_X86_64_GOT32"},
	{4, "R_X86_64_PLT32"},
	{5, "R_X86_64_COPY"},
	{6, "R_X86_64_GLOB_DAT"},
	{7, "R_X86_64_JMP_SLOT"},
	{8, "R_X86_64_RELATIVE"},
	{9, "R_X86_64_GOTPCREL"},
	{10, "R_X86_64_32"},
	{11, "R_X86_64_32S"},
	{12, "R_X86_64_16"},
	{13, "R_X86_64_PC16"},
	{14, "R_X86_64_8"},
	{15, "R_X86_64_PC8"},
	{16, "R_X86_64_DTPMOD64"},
	{17, "R_X86_64_DTPOFF64"},
	{18, "R_X86_64_TPOFF64"},
	{19, "R_X86_64_TLSGD"},
	{20, "R_X86_64_TLSLD"},
	{21, "R_X86_64_DTPOFF32"},
	{22, "R_X86_64_GOTTPOFF"},
	{23, "R_X86_64_TPOFF32"},
	{24, "R_X86_64_PC64"},
	{25, "R_X86_64_GOTOFF64"},
	{26, "R_X86_64_GOTPC32"},
	{27, "R_X86_64_GOT64"},
	{28, "R_X86_64_GOTPCREL64"},
	{29, "R_X86_64_GOTPC64"},
	{30, "R_X86_64_GOTPLT64"},
	{31, "R_X86_64_PLTOFF64"},
	{32, "R_X86_64_SIZE32"},
	{33, "R_X86_64_SIZE64"},
	{34, "R_X86_64_GOTPC32_TLSDESC"},
	{35, "R_X86_64_TLSDESC_CALL"},
	{36, "R_X86_64_TLSDESC"},
	{37, "R_X86_64_IRELATIVE"},
	{38, "R_X86_64_RELATIVE64"},
	{39, "R_X86_64_PC32_BND"},
	{40, "R_X86_64_PLT32_BND"},
	{41, "R_X86_64_GOTPCRELX"},
	{42, "R_X86_64_REX_GOTPCRELX"},
}

func (i R_X86_64) String() string   { return stringify(uint32(i), rx86_64Strings, false) }
func (i R_X86_64) GoString() string { return stringify(uint32(i), rx86_64Strings, true) }

// Relocation types for AArch64 (aka arm64)
type R_AARCH64 int

const (
	R_AARCH64_NONE                            R_AARCH64 = 0
	R_AARCH64_P32_ABS32                       R_AARCH64 = 1
	R_AARCH64_P32_ABS16                       R_AARCH64 = 2
	R_AARCH64_P32_PREL32                      R_AARCH64 = 3
	R_AARCH64_P32_PREL16                      R_AARCH64 = 4
	R_AARCH64_P32_MOVW_UABS_G0                R_AARCH64 = 5
	R_AARCH64_P32_MOVW_UABS_G0_NC             R_AARCH64 = 6
	R_AARCH64_P32_MOVW_UABS_G1                R_AARCH64 = 7
	R_AARCH64_P32_MOVW_SABS_G0                R_AARCH64 = 8
	R_AARCH64_P32_LD_PREL_LO19                R_AARCH64 = 9
	R_AARCH64_P32_ADR_PREL_LO21               R_AARCH64 = 10
	R_AARCH64_P32_ADR_PREL_PG_HI21            R_AARCH64 = 11
	R_AARCH64_P32_ADD_ABS_LO12_NC             R_AARCH64 = 12
	R_AARCH64_P32_LDST8_ABS_LO12_NC           R_AARCH64 = 13
	R_AARCH64_P32_LDST16_ABS_LO12_NC          R_AARCH64 = 14
	R_AARCH64_P32_LDST32_ABS_LO12_NC          R_AARCH64 = 15
	R_AARCH64_P32_LDST64_ABS_LO12_NC          R_AARCH64 = 16
	R_AARCH64_P32_LDST128_ABS_LO12_NC         R_AARCH64 = 17
	R_AARCH64_P32_TSTBR14                     R_AARCH64 = 18
	R_AARCH64_P32_CONDBR19                    R_AARCH64 = 19
	R_AARCH64_P32_JUMP26                      R_AARCH64 = 20
	R_AARCH64_P32_CALL26                      R_AARCH64 = 21
	R_AARCH64_P32_GOT_LD_PREL19               R_AARCH64 = 25
	R_AARCH64_P32_ADR_GOT_PAGE                R_AARCH64 = 26
	R_AARCH64_P32_LD32_GOT_LO12_NC            R_AARCH64 = 27
	R_AARCH64_P32_TLSGD_ADR_PAGE21            R_AARCH64 = 81
	R_AARCH64_P32_TLSGD_ADD_LO12_NC           R_AARCH64 = 82
	R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21   R_AARCH64 = 103
	R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC R_AARCH64 = 104
	R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19    R_AARCH64 = 105
	R_AARCH64_P32_TLSLE_MOVW_TPREL_G1         R_AARCH64 = 106
	R_AARCH64_P32_TLSLE_MOVW_TPREL_G0         R_AARCH64 = 107
	R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC      R_AARCH64 = 108
	R_AARCH64_P32_TLSLE_ADD_TPREL_HI12        R_AARCH64 = 109
	R_AARCH64_P32_TLSLE_ADD_TPREL_LO12        R_AARCH64 = 110
	R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC     R_AARCH64 = 111
	R_AARCH64_P32_TLSDESC_LD_PREL19           R_AARCH64 = 122
	R_AARCH64_P32_TLSDESC_ADR_PREL21          R_AARCH64 = 123
	R_AARCH64_P32_TLSDESC_ADR_PAGE21          R_AARCH64 = 124
	R_AARCH64_P32_TLSDESC_LD32_LO12_NC        R_AARCH64 = 125
	R_AARCH64_P32_TLSDESC_ADD_LO12_NC         R_AARCH64 = 126
	R_AARCH64_P32_TLSDESC_CALL                R_AARCH64 = 127
	R_AARCH64_P32_COPY                        R_AARCH64 = 180
	R_AARCH64_P32_GLOB_DAT                    R_AARCH64 = 181
	R_AARCH64_P32_JUMP_SLOT                   R_AARCH64 = 182
	R_AARCH64_P32_RELATIVE                    R_AARCH64 = 183
	R_AARCH64_P32_TLS_DTPMOD                  R_AARCH64 = 184
	R_AARCH64_P32_TLS_DTPREL                  R_AARCH64 = 185
	R_AARCH64_P32_TLS_TPREL                   R_AARCH64 = 186
	R_AARCH64_P32_TLSDESC                     R_AARCH64 = 187
	R_AARCH64_P32_IRELATIVE                   R_AARCH64 = 188
	R_AARCH64_NULL                            R_AARCH64 = 256
	R_AARCH64_ABS64                           R_AARCH64 = 257
	R_AARCH64_ABS32                           R_AARCH64 = 258
	R_AARCH64_ABS16                           R_AARCH64 = 259
	R_AARCH64_PREL64                          R_AARCH64 = 260
	R_AARCH64_PREL32                          R_AARCH64 = 261
	R_AARCH64_PREL16                          R_AARCH64 = 262
	R_AARCH64_MOVW_UABS_G0                    R_AARCH64 = 263
	R_AARCH64_MOVW_UABS_G0_NC                 R_AARCH64 = 264
	R_AARCH64_MOVW_UABS_G1                    R_AARCH64 = 265
	R_AARCH64_MOVW_UABS_G1_NC                 R_AARCH64 = 266
	R_AARCH64_MOVW_UABS_G2                    R_AARCH64 = 267
	R_AARCH64_MOVW_UABS_G2_NC                 R_AARCH64 = 268
	R_AARCH64_MOVW_UABS_G3                    R_AARCH64 = 269
	R_AARCH64_MOVW_SABS_G0                    R_AARCH64 = 270
	R_AARCH64_MOVW_SABS_G1                    R_AARCH64 = 271
	R_AARCH64_MOVW_SABS_G2                    R_AARCH64 = 272
	R_AARCH64_LD_PREL_LO19                    R_AARCH64 = 273
	R_AARCH64_ADR_PREL_LO21                   R_AARCH64 = 274
	R_AARCH64_ADR_PREL_PG_HI21                R_AARCH64 = 275
	R_AARCH64_ADR_PREL_PG_HI21_NC             R_AARCH64 = 276
	R_AARCH64_ADD_ABS_LO12_NC                 R_AARCH64 = 277
	R_AARCH64_LDST8_ABS_LO12_NC               R_AARCH64 = 278
	R_AARCH64_TSTBR14                         R_AARCH64 = 279
	R_AARCH64_CONDBR19                        R_AARCH64 = 280
	R_AARCH64_JUMP26                          R_AARCH64 = 282
	R_AARCH64_CALL26                          R_AARCH64 = 283
	R_AARCH64_LDST16_ABS_LO12_NC              R_AARCH64 = 284
	R_AARCH64_LDST32_ABS_LO12_NC              R_AARCH64 = 285
	R_AARCH64_LDST64_ABS_LO12_NC              R_AARCH64 = 286
	R_AARCH64_LDST128_ABS_LO12_NC             R_AARCH64 = 299
	R_AARCH64_GOT_LD_PREL19                   R_AARCH64 = 309
	R_AARCH64_LD64_GOTOFF_LO15                R_AARCH64 = 310
	R_AARCH64_ADR_GOT_PAGE                    R_AARCH64 = 311
	R_AARCH64_LD64_GOT_LO12_NC                R_AARCH64 = 312
	R_AARCH64_LD64_GOTPAGE_LO15               R_AARCH64 = 313
	R_AARCH64_TLSGD_ADR_PREL21                R_AARCH64 = 512
	R_AARCH64_TLSGD_ADR_PAGE21                R_AARCH64 = 513
	R_AARCH64_TLSGD_ADD_LO12_NC               R_AARCH64 = 514
	R_AARCH64_TLSGD_MOVW_G1                   R_AARCH64 = 515
	R_AARCH64_TLSGD_MOVW_G0_NC                R_AARCH64 = 516
	R_AARCH64_TLSLD_ADR_PREL21                R_AARCH64 = 517
	R_AARCH64_TLSLD_ADR_PAGE21                R_AARCH64 = 518
	R_AARCH64_TLSIE_MOVW_GOTTPREL_G1          R_AARCH64 = 539
	R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC       R_AARCH64 = 540
	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21       R_AARCH64 = 541
	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC     R_AARCH64 = 542
	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19        R_AARCH64 = 543
	R_AARCH64_TLSLE_MOVW_TPREL_G2             R_AARCH64 = 544
	R_AARCH64_TLSLE_MOVW_TPREL_G1             R_AARCH64 = 545
	R_AARCH64_TLSLE_MOVW_TPREL_G1_NC          R_AARCH64 = 546
	R_AARCH64_TLSLE_MOVW_TPREL_G0             R_AARCH64 = 547
	R_AARCH64_TLSLE_MOVW_TPREL_G0_NC          R_AARCH64 = 548
	R_AARCH64_TLSLE_ADD_TPREL_HI12            R_AARCH64 = 549
	R_AARCH64_TLSLE_ADD_TPREL_LO12            R_AARCH64 = 550
	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC         R_AARCH64 = 551
	R_AARCH64_TLSDESC_LD_PREL19               R_AARCH64 = 560
	R_AARCH64_TLSDESC_ADR_PREL21              R_AARCH64 = 561
	R_AARCH64_TLSDESC_ADR_PAGE21              R_AARCH64 = 562
	R_AARCH64_TLSDESC_LD64_LO12_NC            R_AARCH64 = 563
	R_AARCH64_TLSDESC_ADD_LO12_NC             R_AARCH64 = 564
	R_AARCH64_TLSDESC_OFF_G1                  R_AARCH64 = 565
	R_AARCH64_TLSDESC_OFF_G0_NC               R_AARCH64 = 566
	R_AARCH64_TLSDESC_LDR                     R_AARCH64 = 567
	R_AARCH64_TLSDESC_ADD                     R_AARCH64 = 568
	R_AARCH64_TLSDESC_CALL                    R_AARCH64 = 569
	R_AARCH64_TLSLE_LDST128_TPREL_LO12        R_AARCH64 = 570
	R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC     R_AARCH64 = 571
	R_AARCH64_TLSLD_LDST128_DTPREL_LO12       R_AARCH64 = 572
	R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC    R_AARCH64 = 573
	R_AARCH64_COPY                            R_AARCH64 = 1024
	R_AARCH64_GLOB_DAT                        R_AARCH64 = 1025
	R_AARCH64_JUMP_SLOT                       R_AARCH64 = 1026
	R_AARCH64_RELATIVE                        R_AARCH64 = 1027
	R_AARCH64_TLS_DTPMOD64                    R_AARCH64 = 1028
	R_AARCH64_TLS_DTPREL64                    R_AARCH64 = 1029
	R_AARCH64_TLS_TPREL64                     R_AARCH64 = 1030
	R_AARCH64_TLSDESC                         R_AARCH64 = 1031
	R_AARCH64_IRELATIVE                       R_AARCH64 = 1032
)

var raarch64Strings = []flagName{
	{0, "R_AARCH64_NONE"},
	{1, "R_AARCH64_P32_ABS32"},
	{2, "R_AARCH64_P32_ABS16"},
	{3, "R_AARCH64_P32_PREL32"},
	{4, "R_AARCH64_P32_PREL16"},
	{5, "R_AARCH64_P32_MOVW_UABS_G0"},
	{6, "R_AARCH64_P32_MOVW_UABS_G0_NC"},
	{7, "R_AARCH64_P32_MOVW_UABS_G1"},
	{8, "R_AARCH64_P32_MOVW_SABS_G0"},
	{9, "R_AARCH64_P32_LD_PREL_LO19"},
	{10, "R_AARCH64_P32_ADR_PREL_LO21"},
	{11, "R_AARCH64_P32_ADR_PREL_PG_HI21"},
	{12, "R_AARCH64_P32_ADD_ABS_LO12_NC"},
	{13, "R_AARCH64_P32_LDST8_ABS_LO12_NC"},
	{14, "R_AARCH64_P32_LDST16_ABS_LO12_NC"},
	{15, "R_AARCH64_P32_LDST32_ABS_LO12_NC"},
	{16, "R_AARCH64_P32_LDST64_ABS_LO12_NC"},
	{17, "R_AARCH64_P32_LDST128_ABS_LO12_NC"},
	{18, "R_AARCH64_P32_TSTBR14"},
	{19, "R_AARCH64_P32_CONDBR19"},
	{20, "R_AARCH64_P32_JUMP26"},
	{21, "R_AARCH64_P32_CALL26"},
	{25, "R_AARCH64_P32_GOT_LD_PREL19"},
	{26, "R_AARCH64_P32_ADR_GOT_PAGE"},
	{27, "R_AARCH64_P32_LD32_GOT_LO12_NC"},
	{81, "R_AARCH64_P32_TLSGD_ADR_PAGE21"},
	{82, "R_AARCH64_P32_TLSGD_ADD_LO12_NC"},
	{103, "R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21"},
	{104, "R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC"},
	{105, "R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19"},
	{106, "R_AARCH64_P32_TLSLE_MOVW_TPREL_G1"},
	{107, "R_AARCH64_P32_TLSLE_MOVW_TPREL_G0"},
	{108, "R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC"},
	{109, "R_AARCH64_P32_TLSLE_ADD_TPREL_HI12"},
	{110, "R_AARCH64_P32_TLSLE_ADD_TPREL_LO12"},
	{111, "R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC"},
	{122, "R_AARCH64_P32_TLSDESC_LD_PREL19"},
	{123, "R_AARCH64_P32_TLSDESC_ADR_PREL21"},
	{124, "R_AARCH64_P32_TLSDESC_ADR_PAGE21"},
	{125, "R_AARCH64_P32_TLSDESC_LD32_LO12_NC"},
	{126, "R_AARCH64_P32_TLSDESC_ADD_LO12_NC"},
	{127, "R_AARCH64_P32_TLSDESC_CALL"},
	{180, "R_AARCH64_P32_COPY"},
	{181, "R_AARCH64_P32_GLOB_DAT"},
	{182, "R_AARCH64_P32_JUMP_SLOT"},
	{183, "R_AARCH64_P32_RELATIVE"},
	{184, "R_AARCH64_P32_TLS_DTPMOD"},
	{185, "R_AARCH64_P32_TLS_DTPREL"},
	{186, "R_AARCH64_P32_TLS_TPREL"},
	{187, "R_AARCH64_P32_TLSDESC"},
	{188, "R_AARCH64_P32_IRELATIVE"},
	{256, "R_AARCH64_NULL"},
	{257, "R_AARCH64_ABS64"},
	{258, "R_AARCH64_ABS32"},
	{259, "R_AARCH64_ABS16"},
	{260, "R_AARCH64_PREL64"},
	{261, "R_AARCH64_PREL32"},
	{262, "R_AARCH64_PREL16"},
	{263, "R_AARCH64_MOVW_UABS_G0"},
	{264, "R_AARCH64_MOVW_UABS_G0_NC"},
	{265, "R_AARCH64_MOVW_UABS_G1"},
	{266, "R_AARCH64_MOVW_UABS_G1_NC"},
	{267, "R_AARCH64_MOVW_UABS_G2"},
	{268, "R_AARCH64_MOVW_UABS_G2_NC"},
	{269, "R_AARCH64_MOVW_UABS_G3"},
	{270, "R_AARCH64_MOVW_SABS_G0"},
	{271, "R_AARCH64_MOVW_SABS_G1"},
	{272, "R_AARCH64_MOVW_SABS_G2"},
	{273, "R_AARCH64_LD_PREL_LO19"},
	{274, "R_AARCH64_ADR_PREL_LO21"},
	{275, "R_AARCH64_ADR_PREL_PG_HI21"},
	{276, "R_AARCH64_ADR_PREL_PG_HI21_NC"},
	{277, "R_AARCH64_ADD_ABS_LO12_NC"},
	{278, "R_AARCH64_LDST8_ABS_LO12_NC"},
	{279, "R_AARCH64_TSTBR14"},
	{280, "R_AARCH64_CONDBR19"},
	{282, "R_AARCH64_JUMP26"},
	{283, "R_AARCH64_CALL26"},
	{284, "R_AARCH64_LDST16_ABS_LO12_NC"},
	{285, "R_AARCH64_LDST32_ABS_LO12_NC"},
	{286, "R_AARCH64_LDST64_ABS_LO12_NC"},
	{299, "R_AARCH64_LDST128_ABS_LO12_NC"},
	{309, "R_AARCH64_GOT_LD_PREL19"},
	{310, "R_AARCH64_LD64_GOTOFF_LO15"},
	{311, "R_AARCH64_ADR_GOT_PAGE"},
	{312, "R_AARCH64_LD64_GOT_LO12_NC"},
	{313, "R_AARCH64_LD64_GOTPAGE_LO15"},
	{512, "R_AARCH64_TLSGD_ADR_PREL21"},
	{513, "R_AARCH64_TLSGD_ADR_PAGE21"},
	{514, "R_AARCH64_TLSGD_ADD_LO12_NC"},
	{515, "R_AARCH64_TLSGD_MOVW_G1"},
	{516, "R_AARCH64_TLSGD_MOVW_G0_NC"},
	{517, "R_AARCH64_TLSLD_ADR_PREL21"},
	{518, "R_AARCH64_TLSLD_ADR_PAGE21"},
	{539, "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1"},
	{540, "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC"},
	{541, "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21"},
	{542, "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC"},
	{543, "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19"},
	{544, "R_AARCH64_TLSLE_MOVW_TPREL_G2"},
	{545, "R_AARCH64_TLSLE_MOVW_TPREL_G1"},
	{546, "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC"},
	{547, "R_AARCH64_TLSLE_MOVW_TPREL_G0"},
	{548, "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC"},
	{549, "R_AARCH64_TLSLE_ADD_TPREL_HI12"},
	{550, "R_AARCH64_TLSLE_ADD_TPREL_LO12"},
	{551, "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC"},
	{560, "R_AARCH64_TLSDESC_LD_PREL19"},
	{561, "R_AARCH64_TLSDESC_ADR_PREL21"},
	{562, "R_AARCH64_TLSDESC_ADR_PAGE21"},
	{563, "R_AARCH64_TLSDESC_LD64_LO12_NC"},
	{564, "R_AARCH64_TLSDESC_ADD_LO12_NC"},
	{565, "R_AARCH64_TLSDESC_OFF_G1"},
	{566, "R_AARCH64_TLSDESC_OFF_G0_NC"},
	{567, "R_AARCH64_TLSDESC_LDR"},
	{568, "R_AARCH64_TLSDESC_ADD"},
	{569, "R_AARCH64_TLSDESC_CALL"},
	{570, "R_AARCH64_TLSLE_LDST128_TPREL_LO12"},
	{571, "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC"},
	{572, "R_AARCH64_TLSLD_LDST128_DTPREL_LO12"},
	{573, "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC"},
	{1024, "R_AARCH64_COPY"},
	{1025, "R_AARCH64_GLOB_DAT"},
	{1026, "R_AARCH64_JUMP_SLOT"},
	{1027, "R_AARCH64_RELATIVE"},
	{1028, "R_AARCH64_TLS_DTPMOD64"},
	{1029, "R_AARCH64_TLS_DTPREL64"},
	{1030, "R_AARCH64_TLS_TPREL64"},
	{1031, "R_AARCH64_TLSDESC"},
	{1032, "R_AARCH64_IRELATIVE"},
}

func (i R_AARCH64) String() string   { return stringify(uint32(i), raarch64Strings, false) }
func (i R_AARCH64) GoString() string { return stringify(uint32(i), raarch64Strings, true) }

// Relocation types for Alpha.
type R_ALPHA int

const (
	R_ALPHA_NONE           R_ALPHA = 0  // No reloc
	R_ALPHA_REFLONG        R_ALPHA = 1  // Direct 32 bit
	R_ALPHA_REFQUAD        R_ALPHA = 2  // Direct 64 bit
	R_ALPHA_GPREL32        R_ALPHA = 3  // GP relative 32 bit
	R_ALPHA_LITERAL        R_ALPHA = 4  // GP relative 16 bit w/optimization
	R_ALPHA_LITUSE         R_ALPHA = 5  // Optimization hint for LITERAL
	R_ALPHA_GPDISP         R_ALPHA = 6  // Add displacement to GP
	R_ALPHA_BRADDR         R_ALPHA = 7  // PC+4 relative 23 bit shifted
	R_ALPHA_HINT           R_ALPHA = 8  // PC+4 relative 16 bit shifted
	R_ALPHA_SREL16         R_ALPHA = 9  // PC relative 16 bit
	R_ALPHA_SREL32         R_ALPHA = 10 // PC relative 32 bit
	R_ALPHA_SREL64         R_ALPHA = 11 // PC relative 64 bit
	R_ALPHA_OP_PUSH        R_ALPHA = 12 // OP stack push
	R_ALPHA_OP_STORE       R_ALPHA = 13 // OP stack pop and store
	R_ALPHA_OP_PSUB        R_ALPHA = 14 // OP stack subtract
	R_ALPHA_OP_PRSHIFT     R_ALPHA = 15 // OP stack right shift
	R_ALPHA_GPVALUE        R_ALPHA = 16
	R_ALPHA_GPRELHIGH      R_ALPHA = 17
	R_ALPHA_GPRELLOW       R_ALPHA = 18
	R_ALPHA_IMMED_GP_16    R_ALPHA = 19
	R_ALPHA_IMMED_GP_HI32  R_ALPHA = 20
	R_ALPHA_IMMED_SCN_HI32 R_ALPHA = 21
	R_ALPHA_IMMED_BR_HI32  R_ALPHA = 22
	R_ALPHA_IMMED_LO32     R_ALPHA = 23
	R_ALPHA_COPY           R_ALPHA = 24 // Copy symbol at runtime
	R_ALPHA_GLOB_DAT       R_ALPHA = 25 // Create GOT entry
	R_ALPHA_JMP_SLOT       R_ALPHA = 26 // Create PLT entry
	R_ALPHA_RELATIVE       R_ALPHA = 27 // Adjust by program base
)

var ralphaStrings = []flagName{
	{0, "R_ALPHA_NONE"},
	{1, "R_ALPHA_REFLONG"},
	{2, "R_ALPHA_REFQUAD"},
	{3, "R_ALPHA_GPREL32"},
	{4, "R_ALPHA_LITERAL"},
	{5, "R_ALPHA_LITUSE"},
	{6, "R_ALPHA_GPDISP"},
	{7, "R_ALPHA_BRADDR"},
	{8, "R_ALPHA_HINT"},
	{9, "R_ALPHA_SREL16"},
	{10, "R_ALPHA_SREL32"},
	{11, "R_ALPHA_SREL64"},
	{12, "R_ALPHA_OP_PUSH"},
	{13, "R_ALPHA_OP_STORE"},
	{14, "R_ALPHA_OP_PSUB"},
	{15, "R_ALPHA_OP_PRSHIFT"},
	{16, "R_ALPHA_GPVALUE"},
	{17, "R_ALPHA_GPRELHIGH"},
	{18, "R_ALPHA_GPRELLOW"},
	{19, "R_ALPHA_IMMED_GP_16"},
	{20, "R_ALPHA_IMMED_GP_HI32"},
	{21, "R_ALPHA_IMMED_SCN_HI32"},
	{22, "R_ALPHA_IMMED_BR_HI32"},
	{23, "R_ALPHA_IMMED_LO32"},
	{24, "R_ALPHA_COPY"},
	{25, "R_ALPHA_GLOB_DAT"},
	{26, "R_ALPHA_JMP_SLOT"},
	{27, "R_ALPHA_RELATIVE"},
}

func (i R_ALPHA) String() string   { return stringify(uint32(i), ralphaStrings, false) }
func (i R_ALPHA) GoString() string { return stringify(uint32(i), ralphaStrings, true) }

// Relocation types for ARM.
type R_ARM int

const (
	R_ARM_NONE               R_ARM = 0 // No relocation.
	R_ARM_PC24               R_ARM = 1
	R_ARM_ABS32              R_ARM = 2
	R_ARM_REL32              R_ARM = 3
	R_ARM_PC13               R_ARM = 4
	R_ARM_ABS16              R_ARM = 5
	R_ARM_ABS12              R_ARM = 6
	R_ARM_THM_ABS5           R_ARM = 7
	R_ARM_ABS8               R_ARM = 8
	R_ARM_SBREL32            R_ARM = 9
	R_ARM_THM_PC22           R_ARM = 10
	R_ARM_THM_PC8            R_ARM = 11
	R_ARM_AMP_VCALL9         R_ARM = 12
	R_ARM_SWI24              R_ARM = 13
	R_ARM_THM_SWI8           R_ARM = 14
	R_ARM_XPC25              R_ARM = 15
	R_ARM_THM_XPC22          R_ARM = 16
	R_ARM_TLS_DTPMOD32       R_ARM = 17
	R_ARM_TLS_DTPOFF32       R_ARM = 18
	R_ARM_TLS_TPOFF32        R_ARM = 19
	R_ARM_COPY               R_ARM = 20 // Copy data from shared object.
	R_ARM_GLOB_DAT           R_ARM = 21 // Set GOT entry to data address.
	R_ARM_JUMP_SLOT          R_ARM = 22 // Set GOT entry to code address.
	R_ARM_RELATIVE           R_ARM = 23 // Add load address of shared object.
	R_ARM_GOTOFF             R_ARM = 24 // Add GOT-relative symbol address.
	R_ARM_GOTPC              R_ARM = 25 // Add PC-relative GOT table address.
	R_ARM_GOT32              R_ARM = 26 // Add PC-relative GOT offset.
	R_ARM_PLT32              R_ARM = 27 // Add PC-relative PLT offset.
	R_ARM_CALL               R_ARM = 28
	R_ARM_JUMP24             R_ARM = 29
	R_ARM_THM_JUMP24         R_ARM = 30
	R_ARM_BASE_ABS           R_ARM = 31
	R_ARM_ALU_PCREL_7_0      R_ARM = 32
	R_ARM_ALU_PCREL_15_8     R_ARM = 33
	R_ARM_ALU_PCREL_23_15    R_ARM = 34
	R_ARM_LDR_SBREL_11_10_NC R_ARM = 35
	R_ARM_ALU_SBREL_19_12_NC R_ARM = 36
	R_ARM_ALU_SBREL_27_20_CK R_ARM = 37
	R_ARM_TARGET1            R_ARM = 38
	R_ARM_SBREL31            R_ARM = 39
	R_ARM_V4BX               R_ARM = 40
	R_ARM_TARGET2            R_ARM = 41
	R_ARM_PREL31             R_ARM = 42
	R_ARM_MOVW_ABS_NC        R_ARM = 43
	R_ARM_MOVT_ABS           R_ARM = 44
	R_ARM_MOVW_PREL_NC       R_ARM = 45
	R_ARM_MOVT_PREL          R_ARM = 46
	R_ARM_THM_MOVW_ABS_NC    R_ARM = 47
	R_ARM_THM_MOVT_ABS       R_ARM = 48
	R_ARM_THM_MOVW_PREL_NC   R_ARM = 49
	R_ARM_THM_MOVT_PREL      R_ARM = 50
	R_ARM_THM_JUMP19         R_ARM = 51
	R_ARM_THM_JUMP6          R_ARM = 52
	R_ARM_THM_ALU_PREL_11_0  R_ARM = 53
	R_ARM_THM_PC12           R_ARM = 54
	R_ARM_ABS32_NOI          R_ARM = 55
	R_ARM_REL32_NOI          R_ARM = 56
	R_ARM_ALU_PC_G0_NC       R_ARM = 57
	R_ARM_ALU_PC_G0          R_ARM = 58
	R_ARM_ALU_PC_G1_NC       R_ARM = 59
	R_ARM_ALU_PC_G1          R_ARM = 60
	R_ARM_ALU_PC_G2          R_ARM = 61
	R_ARM_LDR_PC_G1          R_ARM = 62
	R_ARM_LDR_PC_G2          R_ARM = 63
	R_ARM_LDRS_PC_G0         R_ARM = 64
	R_ARM_LDRS_PC_G1         R_ARM = 65
	R_ARM_LDRS_PC_G2         R_ARM = 66
	R_ARM_LDC_PC_G0          R_ARM = 67
	R_ARM_LDC_PC_G1          R_ARM = 68
	R_ARM_LDC_PC_G2          R_ARM = 69
	R_ARM_ALU_SB_G0_NC       R_ARM = 70
	R_ARM_ALU_SB_G0          R_ARM = 71
	R_ARM_ALU_SB_G1_NC       R_ARM = 72
	R_ARM_ALU_SB_G1          R_ARM = 73
	R_ARM_ALU_SB_G2          R_ARM = 74
	R_ARM_LDR_SB_G0          R_ARM = 75
	R_ARM_LDR_SB_G1          R_ARM = 76
	R_ARM_LDR_SB_G2          R_ARM = 77
	R_ARM_LDRS_SB_G0         R_ARM = 78
	R_ARM_LDRS_SB_G1         R_ARM = 79
	R_ARM_LDRS_SB_G2         R_ARM = 80
	R_ARM_LDC_SB_G0          R_ARM = 81
	R_ARM_LDC_SB_G1          R_ARM = 82
	R_ARM_LDC_SB_G2          R_ARM = 83
	R_ARM_MOVW_BREL_NC       R_ARM = 84
	R_ARM_MOVT_BREL          R_ARM = 85
	R_ARM_MOVW_BREL          R_ARM = 86
	R_ARM_THM_MOVW_BREL_NC   R_ARM = 87
	R_ARM_THM_MOVT_BREL      R_ARM = 88
	R_ARM_THM_MOVW_BREL      R_ARM = 89
	R_ARM_TLS_GOTDESC        R_ARM = 90
	R_ARM_TLS_CALL           R_ARM = 91
	R_ARM_TLS_DESCSEQ        R_ARM = 92
	R_ARM_THM_TLS_CALL       R_ARM = 93
	R_ARM_PLT32_ABS          R_ARM = 94
	R_ARM_GOT_ABS            R_ARM = 95
	R_ARM_GOT_PREL           R_ARM = 96
	R_ARM_GOT_BREL12         R_ARM = 97
	R_ARM_GOTOFF12           R_ARM = 98
	R_ARM_GOTRELAX           R_ARM = 99
	R_ARM_GNU_VTENTRY        R_ARM = 100
	R_ARM_GNU_VTINHERIT      R_ARM = 101
	R_ARM_THM_JUMP11         R_ARM = 102
	R_ARM_THM_JUMP8          R_ARM = 103
	R_ARM_TLS_GD32           R_ARM = 104
	R_ARM_TLS_LDM32          R_ARM = 105
	R_ARM_TLS_LDO32          R_ARM = 106
	R_ARM_TLS_IE32           R_ARM = 107
	R_ARM_TLS_LE32           R_ARM = 108
	R_ARM_TLS_LDO12          R_ARM = 109
	R_ARM_TLS_LE12           R_ARM = 110
	R_ARM_TLS_IE12GP         R_ARM = 111
	R_ARM_PRIVATE_0          R_ARM = 112
	R_ARM_PRIVATE_1          R_ARM = 113
	R_ARM_PRIVATE_2          R_ARM = 114
	R_ARM_PRIVATE_3          R_ARM = 115
	R_ARM_PRIVATE_4          R_ARM = 116
	R_ARM_PRIVATE_5          R_ARM = 117
	R_ARM_PRIVATE_6          R_ARM = 118
	R_ARM_PRIVATE_7          R_ARM = 119
	R_ARM_PRIVATE_8          R_ARM = 120
	R_ARM_PRIVATE_9          R_ARM = 121
	R_ARM_PRIVATE_10         R_ARM = 122
	R_ARM_PRIVATE_11         R_ARM = 123
	R_ARM_PRIVATE_12         R_ARM = 124
	R_ARM_PRIVATE_13         R_ARM = 125
	R_ARM_PRIVATE_14         R_ARM = 126
	R_ARM_PRIVATE_15         R_ARM = 127
	R_ARM_ME_TOO             R_ARM = 128
	R_ARM_THM_TLS_DESCSEQ16  R_ARM = 129
	R_ARM_THM_TLS_DESCSEQ32  R_ARM = 130
	R_ARM_THM_GOT_BREL12     R_ARM = 131
	R_ARM_THM_ALU_ABS_G0_NC  R_ARM = 132
	R_ARM_THM_ALU_ABS_G1_NC  R_ARM = 133
	R_ARM_THM_ALU_ABS_G2_NC  R_ARM = 134
	R_ARM_THM_ALU_ABS_G3     R_ARM = 135
	R_ARM_IRELATIVE          R_ARM = 160
	R_ARM_RXPC25             R_ARM = 249
	R_ARM_RSBREL32           R_ARM = 250
	R_ARM_THM_RPC22          R_ARM = 251
	R_ARM_RREL32             R_ARM = 252
	R_ARM_RABS32             R_ARM = 253
	R_ARM_RPC24              R_ARM = 254
	R_ARM_RBASE              R_ARM = 255
)

var rarmStrings = []flagName{
	{0, "R_ARM_NONE"},
	{1, "R_ARM_PC24"},
	{2, "R_ARM_ABS32"},
	{3, "R_ARM_REL32"},
	{4, "R_ARM_PC13"},
	{5, "R_ARM_ABS16"},
	{6, "R_ARM_ABS12"},
	{7, "R_ARM_THM_ABS5"},
	{8, "R_ARM_ABS8"},
	{9, "R_ARM_SBREL32"},
	{10, "R_ARM_THM_PC22"},
	{11, "R_ARM_THM_PC8"},
	{12, "R_ARM_AMP_VCALL9"},
	{13, "R_ARM_SWI24"},
	{14, "R_ARM_THM_SWI8"},
	{15, "R_ARM_XPC25"},
	{16, "R_ARM_THM_XPC22"},
	{17, "R_ARM_TLS_DTPMOD32"},
	{18, "R_ARM_TLS_DTPOFF32"},
	{19, "R_ARM_TLS_TPOFF32"},
	{20, "R_ARM_COPY"},
	{21, "R_ARM_GLOB_DAT"},
	{22, "R_ARM_JUMP_SLOT"},
	{23, "R_ARM_RELATIVE"},
	{24, "R_ARM_GOTOFF"},
	{25, "R_ARM_GOTPC"},
	{26, "R_ARM_GOT32"},
	{27, "R_ARM_PLT32"},
	{28, "R_ARM_CALL"},
	{29, "R_ARM_JUMP24"},
	{30, "R_ARM_THM_JUMP24"},
	{31, "R_ARM_BASE_ABS"},
	{32, "R_ARM_ALU_PCREL_7_0"},
	{33, "R_ARM_ALU_PCREL_15_8"},
	{34, "R_ARM_ALU_PCREL_23_15"},
	{35, "R_ARM_LDR_SBREL_11_10_NC"},
	{36, "R_ARM_ALU_SBREL_19_12_NC"},
	{37, "R_ARM_ALU_SBREL_27_20_CK"},
	{38, "R_ARM_TARGET1"},
	{39, "R_ARM_SBREL31"},
	{40, "R_ARM_V4BX"},
	{41, "R_ARM_TARGET2"},
	{42, "R_ARM_PREL31"},
	{43, "R_ARM_MOVW_ABS_NC"},
	{44, "R_ARM_MOVT_ABS"},
	{45, "R_ARM_MOVW_PREL_NC"},
	{46, "R_ARM_MOVT_PREL"},
	{47, "R_ARM_THM_MOVW_ABS_NC"},
	{48, "R_ARM_THM_MOVT_ABS"},
	{49, "R_ARM_THM_MOVW_PREL_NC"},
	{50, "R_ARM_THM_MOVT_PREL"},
	{51, "R_ARM_THM_JUMP19"},
	{52, "R_ARM_THM_JUMP6"},
	{53, "R_ARM_THM_ALU_PREL_11_0"},
	{54, "R_ARM_THM_PC12"},
	{55, "R_ARM_ABS32_NOI"},
	{56, "R_ARM_REL32_NOI"},
	{57, "R_ARM_ALU_PC_G0_NC"},
	{58, "R_ARM_ALU_PC_G0"},
	{59, "R_ARM_ALU_PC_G1_NC"},
	{60, "R_ARM_ALU_PC_G1"},
	{61, "R_ARM_ALU_PC_G2"},
	{62, "R_ARM_LDR_PC_G1"},
	{63, "R_ARM_LDR_PC_G2"},
	{64, "R_ARM_LDRS_PC_G0"},
	{65, "R_ARM_LDRS_PC_G1"},
	{66, "R_ARM_LDRS_PC_G2"},
	{67, "R_ARM_LDC_PC_G0"},
	{68, "R_ARM_LDC_PC_G1"},
	{69, "R_ARM_LDC_PC_G2"},
	{70, "R_ARM_ALU_SB_G0_NC"},
	{71, "R_ARM_ALU_SB_G0"},
	{72, "R_ARM_ALU_SB_G1_NC"},
	{73, "R_ARM_ALU_SB_G1"},
	{74, "R_ARM_ALU_SB_G2"},
	{75, "R_ARM_LDR_SB_G0"},
	{76, "R_ARM_LDR_SB_G1"},
	{77, "R_ARM_LDR_SB_G2"},
	{78, "R_ARM_LDRS_SB_G0"},
	{79, "R_ARM_LDRS_SB_G1"},
	{80, "R_ARM_LDRS_SB_G2"},
	{81, "R_ARM_LDC_SB_G0"},
	{82, "R_ARM_LDC_SB_G1"},
	{83, "R_ARM_LDC_SB_G2"},
	{84, "R_ARM_MOVW_BREL_NC"},
	{85, "R_ARM_MOVT_BREL"},
	{86, "R_ARM_MOVW_BREL"},
	{87, "R_ARM_THM_MOVW_BREL_NC"},
	{88, "R_ARM_THM_MOVT_BREL"},
	{89, "R_ARM_THM_MOVW_BREL"},
	{90, "R_ARM_TLS_GOTDESC"},
	{91, "R_ARM_TLS_CALL"},
	{92, "R_ARM_TLS_DESCSEQ"},
	{93, "R_ARM_THM_TLS_CALL"},
	{94, "R_ARM_PLT32_ABS"},
	{95, "R_ARM_GOT_ABS"},
	{96, "R_ARM_GOT_PREL"},
	{97, "R_ARM_GOT_BREL12"},
	{98, "R_ARM_GOTOFF12"},
	{99, "R_ARM_GOTRELAX"},
	{100, "R_ARM_GNU_VTENTRY"},
	{101, "R_ARM_GNU_VTINHERIT"},
	{102, "R_ARM_THM_JUMP11"},
	{103, "R_ARM_THM_JUMP8"},
	{104, "R_ARM_TLS_GD32"},
	{105, "R_ARM_TLS_LDM32"},
	{106, "R_ARM_TLS_LDO32"},
	{107, "R_ARM_TLS_IE32"},
	{108, "R_ARM_TLS_LE32"},
	{109, "R_ARM_TLS_LDO12"},
	{110, "R_ARM_TLS_LE12"},
	{111, "R_ARM_TLS_IE12GP"},
	{112, "R_ARM_PRIVATE_0"},
	{113, "R_ARM_PRIVATE_1"},
	{114, "R_ARM_PRIVATE_2"},
	{115, "R_ARM_PRIVATE_3"},
	{116, "R_ARM_PRIVATE_4"},
	{117, "R_ARM_PRIVATE_5"},
	{118, "R_ARM_PRIVATE_6"},
	{119, "R_ARM_PRIVATE_7"},
	{120, "R_ARM_PRIVATE_8"},
	{121, "R_ARM_PRIVATE_9"},
	{122, "R_ARM_PRIVATE_10"},
	{123, "R_ARM_PRIVATE_11"},
	{124, "R_ARM_PRIVATE_12"},
	{125, "R_ARM_PRIVATE_13"},
	{126, "R_ARM_PRIVATE_14"},
	{127, "R_ARM_PRIVATE_15"},
	{128, "R_ARM_ME_TOO"},
	{129, "R_ARM_THM_TLS_DESCSEQ16"},
	{130, "R_ARM_THM_TLS_DESCSEQ32"},
	{131, "R_ARM_THM_GOT_BREL12"},
	{132, "R_ARM_THM_ALU_ABS_G0_NC"},
	{133, "R_ARM_THM_ALU_ABS_G1_NC"},
	{134, "R_ARM_THM_ALU_ABS_G2_NC"},
	{135, "R_ARM_THM_ALU_ABS_G3"},
	{160, "R_ARM_IRELATIVE"},
	{249, "R_ARM_RXPC25"},
	{250, "R_ARM_RSBREL32"},
	{251, "R_ARM_THM_RPC22"},
	{252, "R_ARM_RREL32"},
	{253, "R_ARM_RABS32"},
	{254, "R_ARM_RPC24"},
	{255, "R_ARM_RBASE"},
}

func (i R_ARM) String() string   { return stringify(uint32(i), rarmStrings, false) }
func (i R_ARM) GoString() string { return stringify(uint32(i), rarmStrings, true) }

// Relocation types for 386.
type R_386 int

const (
	R_386_NONE          R_386 = 0  // No relocation.
	R_386_32            R_386 = 1  // Add symbol value.
	R_386_PC32          R_386 = 2  // Add PC-relative symbol value.
	R_386_GOT32         R_386 = 3  // Add PC-relative GOT offset.
	R_386_PLT32         R_386 = 4  // Add PC-relative PLT offset.
	R_386_COPY          R_386 = 5  // Copy data from shared object.
	R_386_GLOB_DAT      R_386 = 6  // Set GOT entry to data address.
	R_386_JMP_SLOT      R_386 = 7  // Set GOT entry to code address.
	R_386_RELATIVE      R_386 = 8  // Add load address of shared object.
	R_386_GOTOFF        R_386 = 9  // Add GOT-relative symbol address.
	R_386_GOTPC         R_386 = 10 // Add PC-relative GOT table address.
	R_386_32PLT         R_386 = 11
	R_386_TLS_TPOFF     R_386 = 14 // Negative offset in static TLS block
	R_386_TLS_IE        R_386 = 15 // Absolute address of GOT for -ve static TLS
	R_386_TLS_GOTIE     R_386 = 16 // GOT entry for negative static TLS block
	R_386_TLS_LE        R_386 = 17 // Negative offset relative to static TLS
	R_386_TLS_GD        R_386 = 18 // 32 bit offset to GOT (index,off) pair
	R_386_TLS_LDM       R_386 = 19 // 32 bit offset to GOT (index,zero) pair
	R_386_16            R_386 = 20
	R_386_PC16          R_386 = 21
	R_386_8             R_386 = 22
	R_386_PC8           R_386 = 23
	R_386_TLS_GD_32     R_386 = 24 // 32 bit offset to GOT (index,off) pair
	R_386_TLS_GD_PUSH   R_386 = 25 // pushl instruction for Sun ABI GD sequence
	R_386_TLS_GD_CALL   R_386 = 26 // call instruction for Sun ABI GD sequence
	R_386_TLS_GD_POP    R_386 = 27 // popl instruction for Sun ABI GD sequence
	R_386_TLS_LDM_32    R_386 = 28 // 32 bit offset to GOT (index,zero) pair
	R_386_TLS_LDM_PUSH  R_386 = 29 // pushl instruction for Sun ABI LD sequence
	R_386_TLS_LDM_CALL  R_386 = 30 // call instruction for Sun ABI LD sequence
	R_386_TLS_LDM_POP   R_386 = 31 // popl instruction for Sun ABI LD sequence
	R_386_TLS_LDO_32    R_386 = 32 // 32 bit offset from start of TLS block
	R_386_TLS_IE_32     R_386 = 33 // 32 bit offset to GOT static TLS offset entry
	R_386_TLS_LE_32     R_386 = 34 // 32 bit offset within static TLS block
	R_386_TLS_DTPMOD32  R_386 = 35 // GOT entry containing TLS index
	R_386_TLS_DTPOFF32  R_386 = 36 // GOT entry containing TLS offset
	R_386_TLS_TPOFF32   R_386 = 37 // GOT entry of -ve static TLS offset
	R_386_SIZE32        R_386 = 38
	R_386_TLS_GOTDESC   R_386 = 39
	R_386_TLS_DESC_CALL R_386 = 40
	R_386_TLS_DESC      R_386 = 41
	R_386_IRELATIVE     R_386 = 42
	R_386_GOT32X        R_386 = 43
)

var r386Strings = []flagName{
	{0, "R_386_NONE"},
	{1, "R_386_32"},
	{2, "R_386_PC32"},
	{3, "R_386_GOT32"},
	{4, "R_386_PLT32"},
	{5, "R_386_COPY"},
	{6, "R_386_GLOB_DAT"},
	{7, "R_386_JMP_SLOT"},
	{8, "R_386_RELATIVE"},
	{9, "R_386_GOTOFF"},
	{10, "R_386_GOTPC"},
	{11, "R_386_32PLT"},
	{14, "R_386_TLS_TPOFF"},
	{15, "R_386_TLS_IE"},
	{16, "R_386_TLS_GOTIE"},
	{17, "R_386_TLS_LE"},
	{18, "R_386_TLS_GD"},
	{19, "R_386_TLS_LDM"},
	{20, "R_386_16"},
	{21, "R_386_PC16"},
	{22, "R_386_8"},
	{23, "R_386_PC8"},
	{24, "R_386_TLS_GD_32"},
	{25, "R_386_TLS_GD_PUSH"},
	{26, "R_386_TLS_GD_CALL"},
	{27, "R_386_TLS_GD_POP"},
	{28, "R_386_TLS_LDM_32"},
	{29, "R_386_TLS_LDM_PUSH"},
	{30, "R_386_TLS_LDM_CALL"},
	{31, "R_386_TLS_LDM_POP"},
	{32, "R_386_TLS_LDO_32"},
	{33, "R_386_TLS_IE_32"},
	{34, "R_386_TLS_LE_32"},
	{35, "R_386_TLS_DTPMOD32"},
	{36, "R_386_TLS_DTPOFF32"},
	{37, "R_386_TLS_TPOFF32"},
	{38, "R_386_SIZE32"},
	{39, "R_386_TLS_GOTDESC"},
	{40, "R_386_TLS_DESC_CALL"},
	{41, "R_386_TLS_DESC"},
	{42, "R_386_IRELATIVE"},
	{43, "R_386_GOT32X"},
}

func (i R_386) String() string   { return stringify(uint32(i), r386Strings, false) }
func (i R_386) GoString() string { return stringify(uint32(i), r386Strings, true) }

// Relocation types for MIPS.
type R_MIPS int

const (
	R_MIPS_NONE            R_MIPS = 0
	R_MIPS_16              R_MIPS = 1
	R_MIPS_32              R_MIPS = 2
	R_MIPS_REL32           R_MIPS = 3
	R_MIPS_26              R_MIPS = 4
	R_MIPS_HI16            R_MIPS = 5  // high 16 bits of symbol value
	R_MIPS_LO16            R_MIPS = 6  // low 16 bits of symbol value
	R_MIPS_GPREL16         R_MIPS = 7  // GP-relative reference
	R_MIPS_LITERAL         R_MIPS = 8  // Reference to literal section
	R_MIPS_GOT16           R_MIPS = 9  // Reference to global offset table
	R_MIPS_PC16            R_MIPS = 10 // 16 bit PC relative reference
	R_MIPS_CALL16          R_MIPS = 11 // 16 bit call through glbl offset tbl
	R_MIPS_GPREL32         R_MIPS = 12
	R_MIPS_SHIFT5          R_MIPS = 16
	R_MIPS_SHIFT6          R_MIPS = 17
	R_MIPS_64              R_MIPS = 18
	R_MIPS_GOT_DISP        R_MIPS = 19
	R_MIPS_GOT_PAGE        R_MIPS = 20
	R_MIPS_GOT_OFST        R_MIPS = 21
	R_MIPS_GOT_HI16        R_MIPS = 22
	R_MIPS_GOT_LO16        R_MIPS = 23
	R_MIPS_SUB             R_MIPS = 24
	R_MIPS_INSERT_A        R_MIPS = 25
	R_MIPS_INSERT_B        R_MIPS = 26
	R_MIPS_DELETE          R_MIPS = 27
	R_MIPS_HIGHER          R_MIPS = 28
	R_MIPS_HIGHEST         R_MIPS = 29
	R_MIPS_CALL_HI16       R_MIPS = 30
	R_MIPS_CALL_LO16       R_MIPS = 31
	R_MIPS_SCN_DISP        R_MIPS = 32
	R_MIPS_REL16           R_MIPS = 33
	R_MIPS_ADD_IMMEDIATE   R_MIPS = 34
	R_MIPS_PJUMP           R_MIPS = 35
	R_MIPS_RELGOT          R_MIPS = 36
	R_MIPS_JALR            R_MIPS = 37
	R_MIPS_TLS_DTPMOD32    R_MIPS = 38 // Module number 32 bit
	R_MIPS_TLS_DTPREL32    R_MIPS = 39 // Module-relative offset 32 bit
	R_MIPS_TLS_DTPMOD64    R_MIPS = 40 // Module number 64 bit
	R_MIPS_TLS_DTPREL64    R_MIPS = 41 // Module-relative offset 64 bit
	R_MIPS_TLS_GD          R_MIPS = 42 // 16 bit GOT offset for GD
	R_MIPS_TLS_LDM         R_MIPS = 43 // 16 bit GOT offset for LDM
	R_MIPS_TLS_DTPREL_HI16 R_MIPS = 44 // Module-relative offset, high 16 bits
	R_MIPS_TLS_DTPREL_LO16 R_MIPS = 45 // Module-relative offset, low 16 bits
	R_MIPS_TLS_GOTTPREL    R_MIPS = 46 // 16 bit GOT offset for IE
	R_MIPS_TLS_TPREL32     R_MIPS = 47 // TP-relative offset, 32 bit
	R_MIPS_TLS_TPREL64     R_MIPS = 48 // TP-relative offset, 64 bit
	R_MIPS_TLS_TPREL_HI16  R_MIPS = 49 // TP-relative offset, high 16 bits
	R_MIPS_TLS_TPREL_LO16  R_MIPS = 50 // TP-relative offset, low 16 bits
)

var rmipsStrings = []flagName{
	{0, "R_MIPS_NONE"},
	{1, "R_MIPS_16"},
	{2, "R_MIPS_32"},
	{3, "R_MIPS_REL32"},
	{4, "R_MIPS_26"},
	{5, "R_MIPS_HI16"},
	{6, "R_MIPS_LO16"},
	{7, "R_MIPS_GPREL16"},
	{8, "R_MIPS_LITERAL"},
	{9, "R_MIPS_GOT16"},
	{10, "R_MIPS_PC16"},
	{11, "R_MIPS_CALL16"},
	{12, "R_MIPS_GPREL32"},
	{16, "R_MIPS_SHIFT5"},
	{17, "R_MIPS_SHIFT6"},
	{18, "R_MIPS_64"},
	{19, "R_MIPS_GOT_DISP"},
	{20, "R_MIPS_GOT_PAGE"},
	{21, "R_MIPS_GOT_OFST"},
	{22, "R_MIPS_GOT_HI16"},
	{23, "R_MIPS_GOT_LO16"},
	{24, "R_MIPS_SUB"},
	{25, "R_MIPS_INSERT_A"},
	{26, "R_MIPS_INSERT_B"},
	{27, "R_MIPS_DELETE"},
	{28, "R_MIPS_HIGHER"},
	{29, "R_MIPS_HIGHEST"},
	{30, "R_MIPS_CALL_HI16"},
	{31, "R_MIPS_CALL_LO16"},
	{32, "R_MIPS_SCN_DISP"},
	{33, "R_MIPS_REL16"},
	{34, "R_MIPS_ADD_IMMEDIATE"},
	{35, "R_MIPS_PJUMP"},
	{36, "R_MIPS_RELGOT"},
	{37, "R_MIPS_JALR"},
	{38, "R_MIPS_TLS_DTPMOD32"},
	{39, "R_MIPS_TLS_DTPREL32"},
	{40, "R_MIPS_TLS_DTPMOD64"},
	{41, "R_MIPS_TLS_DTPREL64"},
	{42, "R_MIPS_TLS_GD"},
	{43, "R_MIPS_TLS_LDM"},
	{44, "R_MIPS_TLS_DTPREL_HI16"},
	{45, "R_MIPS_TLS_DTPREL_LO16"},
	{46, "R_MIPS_TLS_GOTTPREL"},
	{47, "R_MIPS_TLS_TPREL32"},
	{48, "R_MIPS_TLS_TPREL64"},
	{49, "R_MIPS_TLS_TPREL_HI16"},
	{50, "R_MIPS_TLS_TPREL_LO16"},
}

func (i R_MIPS) String() string   { return stringify(uint32(i), rmipsStrings, false) }
func (i R_MIPS) GoString() string { return stringify(uint32(i), rmipsStrings, true) }

// Relocation types for PowerPC.
//
// Values that are shared by both R_PPC and R_PPC64 are prefixed with
// R_POWERPC_ in the ELF standard. For the R_PPC type, the relevant
// shared relocations have been renamed with the prefix R_PPC_.
// The original name follows the value in a comment.
type R_PPC int

const (
	R_PPC_NONE            R_PPC = 0  // R_POWERPC_NONE
	R_PPC_ADDR32          R_PPC = 1  // R_POWERPC_ADDR32
	R_PPC_ADDR24          R_PPC = 2  // R_POWERPC_ADDR24
	R_PPC_ADDR16          R_PPC = 3  // R_POWERPC_ADDR16
	R_PPC_ADDR16_LO       R_PPC = 4  // R_POWERPC_ADDR16_LO
	R_PPC_ADDR16_HI       R_PPC = 5  // R_POWERPC_ADDR16_HI
	R_PPC_ADDR16_HA       R_PPC = 6  // R_POWERPC_ADDR16_HA
	R_PPC_ADDR14          R_PPC = 7  // R_POWERPC_ADDR14
	R_PPC_ADDR14_BRTAKEN  R_PPC = 8  // R_POWERPC_ADDR14_BRTAKEN
	R_PPC_ADDR14_BRNTAKEN R_PPC = 9  // R_POWERPC_ADDR14_BRNTAKEN
	R_PPC_REL24           R_PPC = 10 // R_POWERPC_REL24
	R_PPC_REL14           R_PPC = 11 // R_POWERPC_REL14
	R_PPC_REL14_BRTAKEN   R_PPC = 12 // R_POWERPC_REL14_BRTAKEN
	R_PPC_REL14_BRNTAKEN  R_PPC = 13 // R_POWERPC_REL14_BRNTAKEN
	R_PPC_GOT16           R_PPC = 14 // R_POWERPC_GOT16
	R_PPC_GOT16_LO        R_PPC = 15 // R_POWERPC_GOT16_LO
	R_PPC_GOT16_HI        R_PPC = 16 // R_POWERPC_GOT16_HI
	R_PPC_GOT16_HA        R_PPC = 17 // R_POWERPC_GOT16_HA
	R_PPC_PLTREL24        R_PPC = 18
	R_PPC_COPY            R_PPC = 19 // R_POWERPC_COPY
	R_PPC_GLOB_DAT        R_PPC = 20 // R_POWERPC_GLOB_DAT
	R_PPC_JMP_SLOT        R_PPC = 21 // R_POWERPC_JMP_SLOT
	R_PPC_RELATIVE        R_PPC = 22 // R_POWERPC_RELATIVE
	R_PPC_LOCAL24PC       R_PPC = 23
	R_PPC_UADDR32         R_PPC = 24 // R_POWERPC_UADDR32
	R_PPC_UADDR16         R_PPC = 25 // R_POWERPC_UADDR16
	R_PPC_REL32           R_PPC = 26 // R_POWERPC_REL32
	R_PPC_PLT32           R_PPC = 27 // R_POWERPC_PLT32
	R_PPC_PLTREL32        R_PPC = 28 // R_POWERPC_PLTREL32
	R_PPC_PLT16_LO        R_PPC = 29 // R_POWERPC_PLT16_LO
	R_PPC_PLT16_HI        R_PPC = 30 // R_POWERPC_PLT16_HI
	R_PPC_PLT16_HA        R_PPC = 31 // R_POWERPC_PLT16_HA
	R_PPC_SDAREL16        R_PPC = 32
	R_PPC_SECTOFF         R_PPC = 33 // R_POWERPC_SECTOFF
	R_PPC_SECTOFF_LO      R_PPC = 34 // R_POWERPC_SECTOFF_LO
	R_PPC_SECTOFF_HI      R_PPC = 35 // R_POWERPC_SECTOFF_HI
	R_PPC_SECTOFF_HA      R_PPC = 36 // R_POWERPC_SECTOFF_HA
	R_PPC_TLS             R_PPC = 67 // R_POWERPC_TLS
	R_PPC_DTPMOD32        R_PPC = 68 // R_POWERPC_DTPMOD32
	R_PPC_TPREL16         R_PPC = 69 // R_POWERPC_TPREL16
	R_PPC_TPREL16_LO      R_PPC = 70 // R_POWERPC_TPREL16_LO
	R_PPC_TPREL16_HI      R_PPC = 71 // R_POWERPC_TPREL16_HI
	R_PPC_TPREL16_HA      R_PPC = 72 // R_POWERPC_TPREL16_HA
	R_PPC_TPREL32         R_PPC = 73 // R_POWERPC_TPREL32
	R_PPC_DTPREL16        R_PPC = 74 // R_POWERPC_DTPREL16
	R_PPC_DTPREL16_LO     R_PPC = 75 // R_POWERPC_DTPREL16_LO
	R_PPC_DTPREL16_HI     R_PPC = 76 // R_POWERPC_DTPREL16_HI
	R_PPC_DTPREL16_HA     R_PPC = 77 // R_POWERPC_DTPREL16_HA
	R_PPC_DTPREL32        R_PPC = 78 // R_POWERPC_DTPREL32
	R_PPC_GOT_TLSGD16     R_PPC = 79 // R_POWERPC_GOT_TLSGD16
	R_PPC_GOT_TLSGD16_LO  R_PPC = 80 // R_POWERPC_GOT_TLSGD16_LO
	R_PPC_GOT_TLSGD16_HI  R_PPC = 81 // R_POWERPC_GOT_TLSGD16_HI
	R_PPC_GOT_TLSGD16_HA  R_PPC = 82 // R_POWERPC_GOT_TLSGD16_HA
	R_PPC_GOT_TLSLD16     R_PPC = 83 // R_POWERPC_GOT_TLSLD16
	R_PPC_GOT_TLSLD16_LO  R_PPC = 84 // R_POWERPC_GOT_TLSLD16_LO
	R_PPC_GOT_TLSLD16_HI  R_PPC = 85 // R_POWERPC_GOT_TLSLD16_HI
	R_PPC_GOT_TLSLD16_HA  R_PPC = 86 // R_POWERPC_GOT_TLSLD16_HA
	R_PPC_GOT_TPREL16     R_PPC = 87 // R_POWERPC_GOT_TPREL16
	R_PPC_GOT_TPREL16_LO  R_PPC = 88 // R_POWERPC_GOT_TPREL16_LO
	R_PPC_GOT_TPREL16_HI  R_PPC = 89 // R_POWERPC_GOT_TPREL16_HI
	R_PPC_GOT_TPREL16_HA  R_PPC = 90 // R_POWERPC_GOT_TPREL16_HA
	R_PPC_EMB_NADDR32     R_PPC = 101
	R_PPC_EMB_NADDR16     R_PPC = 102
	R_PPC_EMB_NADDR16_LO  R_PPC = 103
	R_PPC_EMB_NADDR16_HI  R_PPC = 104
	R_PPC_EMB_NADDR16_HA  R_PPC = 105
	R_PPC_EMB_SDAI16      R_PPC = 106
	R_PPC_EMB_SDA2I16     R_PPC = 107
	R_PPC_EMB_SDA2REL     R_PPC = 108
	R_PPC_EMB_SDA21       R_PPC = 109
	R_PPC_EMB_MRKREF      R_PPC = 110
	R_PPC_EMB_RELSEC16    R_PPC = 111
	R_PPC_EMB_RELST_LO    R_PPC = 112
	R_PPC_EMB_RELST_HI    R_PPC = 113
	R_PPC_EMB_RELST_HA    R_PPC = 114
	R_PPC_EMB_BIT_FLD     R_PPC = 115
	R_PPC_EMB_RELSDA      R_PPC = 116
)

var rppcStrings = []flagName{
	{0, "R_PPC_NONE"},
	{1, "R_PPC_ADDR32"},
	{2, "R_PPC_ADDR24"},
	{3, "R_PPC_ADDR16"},
	{4, "R_PPC_ADDR16_LO"},
	{5, "R_PPC_ADDR16_HI"},
	{6, "R_PPC_ADDR16_HA"},
	{7, "R_PPC_ADDR14"},
	{8, "R_PPC_ADDR14_BRTAKEN"},
	{9, "R_PPC_ADDR14_BRNTAKEN"},
	{10, "R_PPC_REL24"},
	{11, "R_PPC_REL14"},
	{12, "R_PPC_REL14_BRTAKEN"},
	{13, "R_PPC_REL14_BRNTAKEN"},
	{14, "R_PPC_GOT16"},
	{15, "R_PPC_GOT16_LO"},
	{16, "R_PPC_GOT16_HI"},
	{17, "R_PPC_GOT16_HA"},
	{18, "R_PPC_PLTREL24"},
	{19, "R_PPC_COPY"},
	{20, "R_PPC_GLOB_DAT"},
	{21, "R_PPC_JMP_SLOT"},
	{22, "R_PPC_RELATIVE"},
	{23, "R_PPC_LOCAL24PC"},
	{24, "R_PPC_UADDR32"},
	{25, "R_PPC_UADDR16"},
	{26, "R_PPC_REL32"},
	{27, "R_PPC_PLT32"},
	{28, "R_PPC_PLTREL32"},
	{29, "R_PPC_PLT16_LO"},
	{30, "R_PPC_PLT16_HI"},
	{31, "R_PPC_PLT16_HA"},
	{32, "R_PPC_SDAREL16"},
	{33, "R_PPC_SECTOFF"},
	{34, "R_PPC_SECTOFF_LO"},
	{35, "R_PPC_SECTOFF_HI"},
	{36, "R_PPC_SECTOFF_HA"},
	{67, "R_PPC_TLS"},
	{68, "R_PPC_DTPMOD32"},
	{69, "R_PPC_TPREL16"},
	{70, "R_PPC_TPREL16_LO"},
	{71, "R_PPC_TPREL16_HI"},
	{72, "R_PPC_TPREL16_HA"},
	{73, "R_PPC_TPREL32"},
	{74, "R_PPC_DTPREL16"},
	{75, "R_PPC_DTPREL16_LO"},
	{76, "R_PPC_DTPREL16_HI"},
	{77, "R_PPC_DTPREL16_HA"},
	{78, "R_PPC_DTPREL32"},
	{79, "R_PPC_GOT_TLSGD16"},
	{80, "R_PPC_GOT_TLSGD16_LO"},
	{81, "R_PPC_GOT_TLSGD16_HI"},
	{82, "R_PPC_GOT_TLSGD16_HA"},
	{83, "R_PPC_GOT_TLSLD16"},
	{84, "R_PPC_GOT_TLSLD16_LO"},
	{85, "R_PPC_GOT_TLSLD16_HI"},
	{86, "R_PPC_GOT_TLSLD16_HA"},
	{87, "R_PPC_GOT_TPREL16"},
	{88, "R_PPC_GOT_TPREL16_LO"},
	{89, "R_PPC_GOT_TPREL16_HI"},
	{90, "R_PPC_GOT_TPREL16_HA"},
	{101, "R_PPC_EMB_NADDR32"},
	{102, "R_PPC_EMB_NADDR16"},
	{103, "R_PPC_EMB_NADDR16_LO"},
	{104, "R_PPC_EMB_NADDR16_HI"},
	{105, "R_PPC_EMB_NADDR16_HA"},
	{106, "R_PPC_EMB_SDAI16"},
	{107, "R_PPC_EMB_SDA2I16"},
	{108, "R_PPC_EMB_SDA2REL"},
	{109, "R_PPC_EMB_SDA21"},
	{110, "R_PPC_EMB_MRKREF"},
	{111, "R_PPC_EMB_RELSEC16"},
	{112, "R_PPC_EMB_RELST_LO"},
	{113, "R_PPC_EMB_RELST_HI"},
	{114, "R_PPC_EMB_RELST_HA"},
	{115, "R_PPC_EMB_BIT_FLD"},
	{116, "R_PPC_EMB_RELSDA"},
}

func (i R_PPC) String() string   { return stringify(uint32(i), rppcStrings, false) }
func (i R_PPC) GoString() string { return stringify(uint32(i), rppcStrings, true) }

// Relocation types for 64-bit PowerPC or Power Architecture processors.
//
// Values that are shared by both R_PPC and R_PPC64 are prefixed with
// R_POWERPC_ in the ELF standard. For the R_PPC64 type, the relevant
// shared relocations have been renamed with the prefix R_PPC64_.
// The original name follows the value in a comment.
type R_PPC64 int

const (
	R_PPC64_NONE               R_PPC64 = 0  // R_POWERPC_NONE
	R_PPC64_ADDR32             R_PPC64 = 1  // R_POWERPC_ADDR32
	R_PPC64_ADDR24             R_PPC64 = 2  // R_POWERPC_ADDR24
	R_PPC64_ADDR16             R_PPC64 = 3  // R_POWERPC_ADDR16
	R_PPC64_ADDR16_LO          R_PPC64 = 4  // R_POWERPC_ADDR16_LO
	R_PPC64_ADDR16_HI          R_PPC64 = 5  // R_POWERPC_ADDR16_HI
	R_PPC64_ADDR16_HA          R_PPC64 = 6  // R_POWERPC_ADDR16_HA
	R_PPC64_ADDR14             R_PPC64 = 7  // R_POWERPC_ADDR14
	R_PPC64_ADDR14_BRTAKEN     R_PPC64 = 8  // R_POWERPC_ADDR14_BRTAKEN
	R_PPC64_ADDR14_BRNTAKEN    R_PPC64 = 9  // R_POWERPC_ADDR14_BRNTAKEN
	R_PPC64_REL24              R_PPC64 = 10 // R_POWERPC_REL24
	R_PPC64_REL14              R_PPC64 = 11 // R_POWERPC_REL14
	R_PPC64_REL14_BRTAKEN      R_PPC64 = 12 // R_POWERPC_REL14_BRTAKEN
	R_PPC64_REL14_BRNTAKEN     R_PPC64 = 13 // R_POWERPC_REL14_BRNTAKEN
	R_PPC64_GOT16              R_PPC64 = 14 // R_POWERPC_GOT16
	R_PPC64_GOT16_LO           R_PPC64 = 15 // R_POWERPC_GOT16_LO
	R_PPC64_GOT16_HI           R_PPC64 = 16 // R_POWERPC_GOT16_HI
	R_PPC64_GOT16_HA           R_PPC64 = 17 // R_POWERPC_GOT16_HA
	R_PPC64_JMP_SLOT           R_PPC64 = 21 // R_POWERPC_JMP_SLOT
	R_PPC64_REL32              R_PPC64 = 26 // R_POWERPC_REL32
	R_PPC64_ADDR64             R_PPC64 = 38
	R_PPC64_ADDR16_HIGHER      R_PPC64 = 39
	R_PPC64_ADDR16_HIGHERA     R_PPC64 = 40
	R_PPC64_ADDR16_HIGHEST     R_PPC64 = 41
	R_PPC64_ADDR16_HIGHESTA    R_PPC64 = 42
	R_PPC64_REL64              R_PPC64 = 44
	R_PPC64_TOC16              R_PPC64 = 47
	R_PPC64_TOC16_LO           R_PPC64 = 48
	R_PPC64_TOC16_HI           R_PPC64 = 49
	R_PPC64_TOC16_HA           R_PPC64 = 50
	R_PPC64_TOC                R_PPC64 = 51
	R_PPC64_PLTGOT16           R_PPC64 = 52
	R_PPC64_PLTGOT16_LO        R_PPC64 = 53
	R_PPC64_PLTGOT16_HI        R_PPC64 = 54
	R_PPC64_PLTGOT16_HA        R_PPC64 = 55
	R_PPC64_ADDR16_DS          R_PPC64 = 56
	R_PPC64_ADDR16_LO_DS       R_PPC64 = 57
	R_PPC64_GOT16_DS           R_PPC64 = 58
	R_PPC64_GOT16_LO_DS        R_PPC64 = 59
	R_PPC64_PLT16_LO_DS        R_PPC64 = 60
	R_PPC64_SECTOFF_DS         R_PPC64 = 61
	R_PPC64_SECTOFF_LO_DS      R_PPC64 = 61
	R_PPC64_TOC16_DS           R_PPC64 = 63
	R_PPC64_TOC16_LO_DS        R_PPC64 = 64
	R_PPC64_PLTGOT16_DS        R_PPC64 = 65
	R_PPC64_PLTGOT_LO_DS       R_PPC64 = 66
	R_PPC64_TLS                R_PPC64 = 67 // R_POWERPC_TLS
	R_PPC64_DTPMOD64           R_PPC64 = 68 // R_POWERPC_DTPMOD64
	R_PPC64_TPREL16            R_PPC64 = 69 // R_POWERPC_TPREL16
	R_PPC64_TPREL16_LO         R_PPC64 = 70 // R_POWERPC_TPREL16_LO
	R_PPC64_TPREL16_HI         R_PPC64 = 71 // R_POWERPC_TPREL16_HI
	R_PPC64_TPREL16_HA         R_PPC64 = 72 // R_POWERPC_TPREL16_HA
	R_PPC64_TPREL64            R_PPC64 = 73 // R_POWERPC_TPREL64
	R_PPC64_DTPREL16           R_PPC64 = 74 // R_POWERPC_DTPREL16
	R_PPC64_DTPREL16_LO        R_PPC64 = 75 // R_POWERPC_DTPREL16_LO
	R_PPC64_DTPREL16_HI        R_PPC64 = 76 // R_POWERPC_DTPREL16_HI
	R_PPC64_DTPREL16_HA        R_PPC64 = 77 // R_POWERPC_DTPREL16_HA
	R_PPC64_DTPREL64           R_PPC64 = 78 // R_POWERPC_DTPREL64
	R_PPC64_GOT_TLSGD16        R_PPC64 = 79 // R_POWERPC_GOT_TLSGD16
	R_PPC64_GOT_TLSGD16_LO     R_PPC64 = 80 // R_POWERPC_GOT_TLSGD16_LO
	R_PPC64_GOT_TLSGD16_HI     R_PPC64 = 81 // R_POWERPC_GOT_TLSGD16_HI
	R_PPC64_GOT_TLSGD16_HA     R_PPC64 = 82 // R_POWERPC_GOT_TLSGD16_HA
	R_PPC64_GOT_TLSLD16        R_PPC64 = 83 // R_POWERPC_GOT_TLSLD16
	R_PPC64_GOT_TLSLD16_LO     R_PPC64 = 84 // R_POWERPC_GOT_TLSLD16_LO
	R_PPC64_GOT_TLSLD16_HI     R_PPC64 = 85 // R_POWERPC_GOT_TLSLD16_HI
	R_PPC64_GOT_TLSLD16_HA     R_PPC64 = 86 // R_POWERPC_GOT_TLSLD16_HA
	R_PPC64_GOT_TPREL16_DS     R_PPC64 = 87 // R_POWERPC_GOT_TPREL16_DS
	R_PPC64_GOT_TPREL16_LO_DS  R_PPC64 = 88 // R_POWERPC_GOT_TPREL16_LO_DS
	R_PPC64_GOT_TPREL16_HI     R_PPC64 = 89 // R_POWERPC_GOT_TPREL16_HI
	R_PPC64_GOT_TPREL16_HA     R_PPC64 = 90 // R_POWERPC_GOT_TPREL16_HA
	R_PPC64_GOT_DTPREL16_DS    R_PPC64 = 91 // R_POWERPC_GOT_DTPREL16_DS
	R_PPC64_GOT_DTPREL16_LO_DS R_PPC64 = 92 // R_POWERPC_GOT_DTPREL16_LO_DS
	R_PPC64_GOT_DTPREL16_HI    R_PPC64 = 93 // R_POWERPC_GOT_DTPREL16_HI
	R_PPC64_GOT_DTPREL16_HA    R_PPC64 = 94 // R_POWERPC_GOT_DTPREL16_HA
	R_PPC64_TPREL16_DS         R_PPC64 = 95
	R_PPC64_TPREL16_LO_DS      R_PPC64 = 96
	R_PPC64_TPREL16_HIGHER     R_PPC64 = 97
	R_PPC64_TPREL16_HIGHERA    R_PPC64 = 98
	R_PPC64_TPREL16_HIGHEST    R_PPC64 = 99
	R_PPC64_TPREL16_HIGHESTA   R_PPC64 = 100
	R_PPC64_DTPREL16_DS        R_PPC64 = 101
	R_PPC64_DTPREL16_LO_DS     R_PPC64 = 102
	R_PPC64_DTPREL16_HIGHER    R_PPC64 = 103
	R_PPC64_DTPREL16_HIGHERA   R_PPC64 = 104
	R_PPC64_DTPREL16_HIGHEST   R_PPC64 = 105
	R_PPC64_DTPREL16_HIGHESTA  R_PPC64 = 106
	R_PPC64_TLSGD              R_PPC64 = 107
	R_PPC64_TLSLD              R_PPC64 = 108
	R_PPC64_TOCSAVE            R_PPC64 = 109
	R_PPC64_ADDR16_HIGH        R_PPC64 = 110
	R_PPC64_ADDR16_HIGHA       R_PPC64 = 111
	R_PPC64_TPREL16_HIGH       R_PPC64 = 112
	R_PPC64_TPREL16_HIGHA      R_PPC64 = 113
	R_PPC64_DTPREL16_HIGH      R_PPC64 = 114
	R_PPC64_DTPREL16_HIGHA     R_PPC64 = 115
	R_PPC64_REL24_NOTOC        R_PPC64 = 116
	R_PPC64_ADDR64_LOCAL       R_PPC64 = 117
	R_PPC64_ENTRY              R_PPC64 = 118
	R_PPC64_REL16DX_HA         R_PPC64 = 246 // R_POWERPC_REL16DX_HA
	R_PPC64_JMP_IREL           R_PPC64 = 247
	R_PPC64_IRELATIVE          R_PPC64 = 248 // R_POWERPC_IRELATIVE
	R_PPC64_REL16              R_PPC64 = 249 // R_POWERPC_REL16
	R_PPC64_REL16_LO           R_PPC64 = 250 // R_POWERPC_REL16_LO
	R_PPC64_REL16_HI           R_PPC64 = 251 // R_POWERPC_REL16_HI
	R_PPC64_REL16_HA           R_PPC64 = 252 // R_POWERPC_REL16_HA
)

var rppc64Strings = []flagName{
	{0, "R_PPC64_NONE"},
	{1, "R_PPC64_ADDR32"},
	{2, "R_PPC64_ADDR24"},
	{3, "R_PPC64_ADDR16"},
	{4, "R_PPC64_ADDR16_LO"},
	{5, "R_PPC64_ADDR16_HI"},
	{6, "R_PPC64_ADDR16_HA"},
	{7, "R_PPC64_ADDR14"},
	{8, "R_PPC64_ADDR14_BRTAKEN"},
	{9, "R_PPC64_ADDR14_BRNTAKEN"},
	{10, "R_PPC64_REL24"},
	{11, "R_PPC64_REL14"},
	{12, "R_PPC64_REL14_BRTAKEN"},
	{13, "R_PPC64_REL14_BRNTAKEN"},
	{14, "R_PPC64_GOT16"},
	{15, "R_PPC64_GOT16_LO"},
	{16, "R_PPC64_GOT16_HI"},
	{17, "R_PPC64_GOT16_HA"},
	{21, "R_PPC64_JMP_SLOT"},
	{26, "R_PPC64_REL32"},
	{38, "R_PPC64_ADDR64"},
	{39, "R_PPC64_ADDR16_HIGHER"},
	{40, "R_PPC64_ADDR16_HIGHERA"},
	{41, "R_PPC64_ADDR16_HIGHEST"},
	{42, "R_PPC64_ADDR16_HIGHESTA"},
	{44, "R_PPC64_REL64"},
	{47, "R_PPC64_TOC16"},
	{48, "R_PPC64_TOC16_LO"},
	{49, "R_PPC64_TOC16_HI"},
	{50, "R_PPC64_TOC16_HA"},
	{51, "R_PPC64_TOC"},
	{52, "R_PPC64_PLTGOT16"},
	{53, "R_PPC64_PLTGOT16_LO"},
	{54, "R_PPC64_PLTGOT16_HI"},
	{55, "R_PPC64_PLTGOT16_HA"},
	{56, "R_PPC64_ADDR16_DS"},
	{57, "R_PPC64_ADDR16_LO_DS"},
	{58, "R_PPC64_GOT16_DS"},
	{59, "R_PPC64_GOT16_LO_DS"},
	{60, "R_PPC64_PLT16_LO_DS"},
	{61, "R_PPC64_SECTOFF_DS"},
	{61, "R_PPC64_SECTOFF_LO_DS"},
	{63, "R_PPC64_TOC16_DS"},
	{64, "R_PPC64_TOC16_LO_DS"},
	{65, "R_PPC64_PLTGOT16_DS"},
	{66, "R_PPC64_PLTGOT_LO_DS"},
	{67, "R_PPC64_TLS"},
	{68, "R_PPC64_DTPMOD64"},
	{69, "R_PPC64_TPREL16"},
	{70, "R_PPC64_TPREL16_LO"},
	{71, "R_PPC64_TPREL16_HI"},
	{72, "R_PPC64_TPREL16_HA"},
	{73, "R_PPC64_TPREL64"},
	{74, "R_PPC64_DTPREL16"},
	{75, "R_PPC64_DTPREL16_LO"},
	{76, "R_PPC64_DTPREL16_HI"},
	{77, "R_PPC64_DTPREL16_HA"},
	{78, "R_PPC64_DTPREL64"},
	{79, "R_PPC64_GOT_TLSGD16"},
	{80, "R_PPC64_GOT_TLSGD16_LO"},
	{81, "R_PPC64_GOT_TLSGD16_HI"},
	{82, "R_PPC64_GOT_TLSGD16_HA"},
	{83, "R_PPC64_GOT_TLSLD16"},
	{84, "R_PPC64_GOT_TLSLD16_LO"},
	{85, "R_PPC64_GOT_TLSLD16_HI"},
	{86, "R_PPC64_GOT_TLSLD16_HA"},
	{87, "R_PPC64_GOT_TPREL16_DS"},
	{88, "R_PPC64_GOT_TPREL16_LO_DS"},
	{89, "R_PPC64_GOT_TPREL16_HI"},
	{90, "R_PPC64_GOT_TPREL16_HA"},
	{91, "R_PPC64_GOT_DTPREL16_DS"},
	{92, "R_PPC64_GOT_DTPREL16_LO_DS"},
	{93, "R_PPC64_GOT_DTPREL16_HI"},
	{94, "R_PPC64_GOT_DTPREL16_HA"},
	{95, "R_PPC64_TPREL16_DS"},
	{96, "R_PPC64_TPREL16_LO_DS"},
	{97, "R_PPC64_TPREL16_HIGHER"},
	{98, "R_PPC64_TPREL16_HIGHERA"},
	{99, "R_PPC64_TPREL16_HIGHEST"},
	{100, "R_PPC64_TPREL16_HIGHESTA"},
	{101, "R_PPC64_DTPREL16_DS"},
	{102, "R_PPC64_DTPREL16_LO_DS"},
	{103, "R_PPC64_DTPREL16_HIGHER"},
	{104, "R_PPC64_DTPREL16_HIGHERA"},
	{105, "R_PPC64_DTPREL16_HIGHEST"},
	{106, "R_PPC64_DTPREL16_HIGHESTA"},
	{107, "R_PPC64_TLSGD"},
	{108, "R_PPC64_TLSLD"},
	{109, "R_PPC64_TOCSAVE"},
	{110, "R_PPC64_ADDR16_HIGH"},
	{111, "R_PPC64_ADDR16_HIGHA"},
	{112, "R_PPC64_TPREL16_HIGH"},
	{113, "R_PPC64_TPREL16_HIGHA"},
	{114, "R_PPC64_DTPREL16_HIGH"},
	{115, "R_PPC64_DTPREL16_HIGHA"},
	{116, "R_PPC64_REL24_NOTOC"},
	{117, "R_PPC64_ADDR64_LOCAL"},
	{118, "R_PPC64_ENTRY"},
	{246, "R_PPC64_REL16DX_HA"},
	{247, "R_PPC64_JMP_IREL"},
	{248, "R_PPC64_IRELATIVE"},
	{249, "R_PPC64_REL16"},
	{250, "R_PPC64_REL16_LO"},
	{251, "R_PPC64_REL16_HI"},
	{252, "R_PPC64_REL16_HA"},
}

func (i R_PPC64) String() string   { return stringify(uint32(i), rppc64Strings, false) }
func (i R_PPC64) GoString() string { return stringify(uint32(i), rppc64Strings, true) }

// Relocation types for RISC-V processors.
type R_RISCV int

const (
	R_RISCV_NONE          R_RISCV = 0  // No relocation.
	R_RISCV_32            R_RISCV = 1  // Add 32 bit zero extended symbol value
	R_RISCV_64            R_RISCV = 2  // Add 64 bit symbol value.
	R_RISCV_RELATIVE      R_RISCV = 3  // Add load address of shared object.
	R_RISCV_COPY          R_RISCV = 4  // Copy data from shared object.
	R_RISCV_JUMP_SLOT     R_RISCV = 5  // Set GOT entry to code address.
	R_RISCV_TLS_DTPMOD32  R_RISCV = 6  // 32 bit ID of module containing symbol
	R_RISCV_TLS_DTPMOD64  R_RISCV = 7  // ID of module containing symbol
	R_RISCV_TLS_DTPREL32  R_RISCV = 8  // 32 bit relative offset in TLS block
	R_RISCV_TLS_DTPREL64  R_RISCV = 9  // Relative offset in TLS block
	R_RISCV_TLS_TPREL32   R_RISCV = 10 // 32 bit relative offset in static TLS block
	R_RISCV_TLS_TPREL64   R_RISCV = 11 // Relative offset in static TLS block
	R_RISCV_BRANCH        R_RISCV = 16 // PC-relative branch
	R_RISCV_JAL           R_RISCV = 17 // PC-relative jump
	R_RISCV_CALL          R_RISCV = 18 // PC-relative call
	R_RISCV_CALL_PLT      R_RISCV = 19 // PC-relative call (PLT)
	R_RISCV_GOT_HI20      R_RISCV = 20 // PC-relative GOT reference
	R_RISCV_TLS_GOT_HI20  R_RISCV = 21 // PC-relative TLS IE GOT offset
	R_RISCV_TLS_GD_HI20   R_RISCV = 22 // PC-relative TLS GD reference
	R_RISCV_PCREL_HI20    R_RISCV = 23 // PC-relative reference
	R_RISCV_PCREL_LO12_I  R_RISCV = 24 // PC-relative reference
	R_RISCV_PCREL_LO12_S  R_RISCV = 25 // PC-relative reference
	R_RISCV_HI20          R_RISCV = 26 // Absolute address
	R_RISCV_LO12_I        R_RISCV = 27 // Absolute address
	R_RISCV_LO12_S        R_RISCV = 28 // Absolute address
	R_RISCV_TPREL_HI20    R_RISCV = 29 // TLS LE thread offset
	R_RISCV_TPREL_LO12_I  R_RISCV = 30 // TLS LE thread offset
	R_RISCV_TPREL_LO12_S  R_RISCV = 31 // TLS LE thread offset
	R_RISCV_TPREL_ADD     R_RISCV = 32 // TLS LE thread usage
	R_RISCV_ADD8          R_RISCV = 33 // 8-bit label addition
	R_RISCV_ADD16         R_RISCV = 34 // 16-bit label addition
	R_RISCV_ADD32         R_RISCV = 35 // 32-bit label addition
	R_RISCV_ADD64         R_RISCV = 36 // 64-bit label addition
	R_RISCV_SUB8          R_RISCV = 37 // 8-bit label subtraction
	R_RISCV_SUB16         R_RISCV = 38 // 16-bit label subtraction
	R_RISCV_SUB32         R_RISCV = 39 // 32-bit label subtraction
	R_RISCV_SUB64         R_RISCV = 40 // 64-bit label subtraction
	R_RISCV_GNU_VTINHERIT R_RISCV = 41 // GNU C++ vtable hierarchy
	R_RISCV_GNU_VTENTRY   R_RISCV = 42 // GNU C++ vtable member usage
	R_RISCV_ALIGN         R_RISCV = 43 // Alignment statement
	R_RISCV_RVC_BRANCH    R_RISCV = 44 // PC-relative branch offset
	R_RISCV_RVC_JUMP      R_RISCV = 45 // PC-relative jump offset
	R_RISCV_RVC_LUI       R_RISCV = 46 // Absolute address
	R_RISCV_GPREL_I       R_RISCV = 47 // GP-relative reference
	R_RISCV_GPREL_S       R_RISCV = 48 // GP-relative reference
	R_RISCV_TPREL_I       R_RISCV = 49 // TP-relative TLS LE load
	R_RISCV_TPREL_S       R_RISCV = 50 // TP-relative TLS LE store
	R_RISCV_RELAX         R_RISCV = 51 // Instruction pair can be relaxed
	R_RISCV_SUB6          R_RISCV = 52 // Local label subtraction
	R_RISCV_SET6          R_RISCV = 53 // Local label subtraction
	R_RISCV_SET8          R_RISCV = 54 // Local label subtraction
	R_RISCV_SET16         R_RISCV = 55 // Local label subtraction
	R_RISCV_SET32         R_RISCV = 56 // Local label subtraction
	R_RISCV_32_PCREL      R_RISCV = 57 // 32-bit PC relative
)

var rriscvStrings = []flagName{
	{0, "R_RISCV_NONE"},
	{1, "R_RISCV_32"},
	{2, "R_RISCV_64"},
	{3, "R_RISCV_RELATIVE"},
	{4, "R_RISCV_COPY"},
	{5, "R_RISCV_JUMP_SLOT"},
	{6, "R_RISCV_TLS_DTPMOD32"},
	{7, "R_RISCV_TLS_DTPMOD64"},
	{8, "R_RISCV_TLS_DTPREL32"},
	{9, "R_RISCV_TLS_DTPREL64"},
	{10, "R_RISCV_TLS_TPREL32"},
	{11, "R_RISCV_TLS_TPREL64"},
	{16, "R_RISCV_BRANCH"},
	{17, "R_RISCV_JAL"},
	{18, "R_RISCV_CALL"},
	{19, "R_RISCV_CALL_PLT"},
	{20, "R_RISCV_GOT_HI20"},
	{21, "R_RISCV_TLS_GOT_HI20"},
	{22, "R_RISCV_TLS_GD_HI20"},
	{23, "R_RISCV_PCREL_HI20"},
	{24, "R_RISCV_PCREL_LO12_I"},
	{25, "R_RISCV_PCREL_LO12_S"},
	{26, "R_RISCV_HI20"},
	{27, "R_RISCV_LO12_I"},
	{28, "R_RISCV_LO12_S"},
	{29, "R_RISCV_TPREL_HI20"},
	{30, "R_RISCV_TPREL_LO12_I"},
	{31, "R_RISCV_TPREL_LO12_S"},
	{32, "R_RISCV_TPREL_ADD"},
	{33, "R_RISCV_ADD8"},
	{34, "R_RISCV_ADD16"},
	{35, "R_RISCV_ADD32"},
	{36, "R_RISCV_ADD64"},
	{37, "R_RISCV_SUB8"},
	{38, "R_RISCV_SUB16"},
	{39, "R_RISCV_SUB32"},
	{40, "R_RISCV_SUB64"},
	{41, "R_RISCV_GNU_VTINHERIT"},
	{42, "R_RISCV_GNU_VTENTRY"},
	{43, "R_RISCV_ALIGN"},
	{44, "R_RISCV_RVC_BRANCH"},
	{45, "R_RISCV_RVC_JUMP"},
	{46, "R_RISCV_RVC_LUI"},
	{47, "R_RISCV_GPREL_I"},
	{48, "R_RISCV_GPREL_S"},
	{49, "R_RISCV_TPREL_I"},
	{50, "R_RISCV_TPREL_S"},
	{51, "R_RISCV_RELAX"},
	{52, "R_RISCV_SUB6"},
	{53, "R_RISCV_SET6"},
	{54, "R_RISCV_SET8"},
	{55, "R_RISCV_SET16"},
	{56, "R_RISCV_SET32"},
	{57, "R_RISCV_32_PCREL"},
}

func (i R_RISCV) String() string   { return stringify(uint32(i), rriscvStrings, false) }
func (i R_RISCV) GoString() string { return stringify(uint32(i), rriscvStrings, true) }

// Relocation types for s390x processors.
type R_390 int

const (
	R_390_NONE        R_390 = 0
	R_390_8           R_390 = 1
	R_390_12          R_390 = 2
	R_390_16          R_390 = 3
	R_390_32          R_390 = 4
	R_390_PC32        R_390 = 5
	R_390_GOT12       R_390 = 6
	R_390_GOT32       R_390 = 7
	R_390_PLT32       R_390 = 8
	R_390_COPY        R_390 = 9
	R_390_GLOB_DAT    R_390 = 10
	R_390_JMP_SLOT    R_390 = 11
	R_390_RELATIVE    R_390 = 12
	R_390_GOTOFF      R_390 = 13
	R_390_GOTPC       R_390 = 14
	R_390_GOT16       R_390 = 15
	R_390_PC16        R_390 = 16
	R_390_PC16DBL     R_390 = 17
	R_390_PLT16DBL    R_390 = 18
	R_390_PC32DBL     R_390 = 19
	R_390_PLT32DBL    R_390 = 20
	R_390_GOTPCDBL    R_390 = 21
	R_390_64          R_390 = 22
	R_390_PC64        R_390 = 23
	R_390_GOT64       R_390 = 24
	R_390_PLT64       R_390 = 25
	R_390_GOTENT      R_390 = 26
	R_390_GOTOFF16    R_390 = 27
	R_390_GOTOFF64    R_390 = 28
	R_390_GOTPLT12    R_390 = 29
	R_390_GOTPLT16    R_390 = 30
	R_390_GOTPLT32    R_390 = 31
	R_390_GOTPLT64    R_390 = 32
	R_390_GOTPLTENT   R_390 = 33
	R_390_GOTPLTOFF16 R_390 = 34
	R_390_GOTPLTOFF32 R_390 = 35
	R_390_GOTPLTOFF64 R_390 = 36
	R_390_TLS_LOAD    R_390 = 37
	R_390_TLS_GDCALL  R_390 = 38
	R_390_TLS_LDCALL  R_390 = 39
	R_390_TLS_GD32    R_390 = 40
	R_390_TLS_GD64    R_390 = 41
	R_390_TLS_GOTIE12 R_390 = 42
	R_390_TLS_GOTIE32 R_390 = 43
	R_390_TLS_GOTIE64 R_390 = 44
	R_390_TLS_LDM32   R_390 = 45
	R_390_TLS_LDM64   R_390 = 46
	R_390_TLS_IE32    R_390 = 47
	R_390_TLS_IE64    R_390 = 48
	R_390_TLS_IEENT   R_390 = 49
	R_390_TLS_LE32    R_390 = 50
	R_390_TLS_LE64    R_390 = 51
	R_390_TLS_LDO32   R_390 = 52
	R_390_TLS_LDO64   R_390 = 53
	R_390_TLS_DTPMOD  R_390 = 54
	R_390_TLS_DTPOFF  R_390 = 55
	R_390_TLS_TPOFF   R_390 = 56
	R_390_20          R_390 = 57
	R_390_GOT20       R_390 = 58
	R_390_GOTPLT20    R_390 = 59
	R_390_TLS_GOTIE20 R_390 = 60
)

var r390Strings = []flagName{
	{0, "R_390_NONE"},
	{1, "R_390_8"},
	{2, "R_390_12"},
	{3, "R_390_16"},
	{4, "R_390_32"},
	{5, "R_390_PC32"},
	{6, "R_390_GOT12"},
	{7, "R_390_GOT32"},
	{8, "R_390_PLT32"},
	{9, "R_390_COPY"},
	{10, "R_390_GLOB_DAT"},
	{11, "R_390_JMP_SLOT"},
	{12, "R_390_RELATIVE"},
	{13, "R_390_GOTOFF"},
	{14, "R_390_GOTPC"},
	{15, "R_390_GOT16"},
	{16, "R_390_PC16"},
	{17, "R_390_PC16DBL"},
	{18, "R_390_PLT16DBL"},
	{19, "R_390_PC32DBL"},
	{20, "R_390_PLT32DBL"},
	{21, "R_390_GOTPCDBL"},
	{22, "R_390_64"},
	{23, "R_390_PC64"},
	{24, "R_390_GOT64"},
	{25, "R_390_PLT64"},
	{26, "R_390_GOTENT"},
	{27, "R_390_GOTOFF16"},
	{28, "R_390_GOTOFF64"},
	{29, "R_390_GOTPLT12"},
	{30, "R_390_GOTPLT16"},
	{31, "R_390_GOTPLT32"},
	{32, "R_390_GOTPLT64"},
	{33, "R_390_GOTPLTENT"},
	{34, "R_390_GOTPLTOFF16"},
	{35, "R_390_GOTPLTOFF32"},
	{36, "R_390_GOTPLTOFF64"},
	{37, "R_390_TLS_LOAD"},
	{38, "R_390_TLS_GDCALL"},
	{39, "R_390_TLS_LDCALL"},
	{40, "R_390_TLS_GD32"},
	{41, "R_390_TLS_GD64"},
	{42, "R_390_TLS_GOTIE12"},
	{43, "R_390_TLS_GOTIE32"},
	{44, "R_390_TLS_GOTIE64"},
	{45, "R_390_TLS_LDM32"},
	{46, "R_390_TLS_LDM64"},
	{47, "R_390_TLS_IE32"},
	{48, "R_390_TLS_IE64"},
	{49, "R_390_TLS_IEENT"},
	{50, "R_390_TLS_LE32"},
	{51, "R_390_TLS_LE64"},
	{52, "R_390_TLS_LDO32"},
	{53, "R_390_TLS_LDO64"},
	{54, "R_390_TLS_DTPMOD"},
	{55, "R_390_TLS_DTPOFF"},
	{56, "R_390_TLS_TPOFF"},
	{57, "R_390_20"},
	{58, "R_390_GOT20"},
	{59, "R_390_GOTPLT20"},
	{60, "R_390_TLS_GOTIE20"},
}

func (i R_390) String() string   { return stringify(uint32(i), r390Strings, false) }
func (i R_390) GoString() string { return stringify(uint32(i), r390Strings, true) }

// Relocation types for SPARC.
type R_SPARC int

const (
	R_SPARC_NONE     R_SPARC = 0
	R_SPARC_8        R_SPARC = 1
	R_SPARC_16       R_SPARC = 2
	R_SPARC_32       R_SPARC = 3
	R_SPARC_DISP8    R_SPARC = 4
	R_SPARC_DISP16   R_SPARC = 5
	R_SPARC_DISP32   R_SPARC = 6
	R_SPARC_WDISP30  R_SPARC = 7
	R_SPARC_WDISP22  R_SPARC = 8
	R_SPARC_HI22     R_SPARC = 9
	R_SPARC_22       R_SPARC = 10
	R_SPARC_13       R_SPARC = 11
	R_SPARC_LO10     R_SPARC = 12
	R_SPARC_GOT10    R_SPARC = 13
	R_SPARC_GOT13    R_SPARC = 14
	R_SPARC_GOT22    R_SPARC = 15
	R_SPARC_PC10     R_SPARC = 16
	R_SPARC_PC22     R_SPARC = 17
	R_SPARC_WPLT30   R_SPARC = 18
	R_SPARC_COPY     R_SPARC = 19
	R_SPARC_GLOB_DAT R_SPARC = 20
	R_SPARC_JMP_SLOT R_SPARC = 21
	R_SPARC_RELATIVE R_SPARC = 22
	R_SPARC_UA32     R_SPARC = 23
	R_SPARC_PLT32    R_SPARC = 24
	R_SPARC_HIPLT22  R_SPARC = 25
	R_SPARC_LOPLT10  R_SPARC = 26
	R_SPARC_PCPLT32  R_SPARC = 27
	R_SPARC_PCPLT22  R_SPARC = 28
	R_SPARC_PCPLT10  R_SPARC = 29
	R_SPARC_10       R_SPARC = 30
	R_SPARC_11       R_SPARC = 31
	R_SPARC_64       R_SPARC = 32
	R_SPARC_OLO10    R_SPARC = 33
	R_SPARC_HH22     R_SPARC = 34
	R_SPARC_HM10     R_SPARC = 35
	R_SPARC_LM22     R_SPARC = 36
	R_SPARC_PC_HH22  R_SPARC = 37
	R_SPARC_PC_HM10  R_SPARC = 38
	R_SPARC_PC_LM22  R_SPARC = 39
	R_SPARC_WDISP16  R_SPARC = 40
	R_SPARC_WDISP19  R_SPARC = 41
	R_SPARC_GLOB_JMP R_SPARC = 42
	R_SPARC_7        R_SPARC = 43
	R_SPARC_5        R_SPARC = 44
	R_SPARC_6        R_SPARC = 45
	R_SPARC_DISP64   R_SPARC = 46
	R_SPARC_PLT64    R_SPARC = 47
	R_SPARC_HIX22    R_SPARC = 48
	R_SPARC_LOX10    R_SPARC = 49
	R_SPARC_H44      R_SPARC = 50
	R_SPARC_M44      R_SPARC = 51
	R_SPARC_L44      R_SPARC = 52
	R_SPARC_REGISTER R_SPARC = 53
	R_SPARC_UA64     R_SPARC = 54
	R_SPARC_UA16     R_SPARC = 55
)

var rsparcStrings = []flagName{
	{0, "R_SPARC_NONE"},
	{1, "R_SPARC_8"},
	{2, "R_SPARC_16"},
	{3, "R_SPARC_32"},
	{4, "R_SPARC_DISP8"},
	{5, "R_SPARC_DISP16"},
	{6, "R_SPARC_DISP32"},
	{7, "R_SPARC_WDISP30"},
	{8, "R_SPARC_WDISP22"},
	{9, "R_SPARC_HI22"},
	{10, "R_SPARC_22"},
	{11, "R_SPARC_13"},
	{12, "R_SPARC_LO10"},
	{13, "R_SPARC_GOT10"},
	{14, "R_SPARC_GOT13"},
	{15, "R_SPARC_GOT22"},
	{16, "R_SPARC_PC10"},
	{17, "R_SPARC_PC22"},
	{18, "R_SPARC_WPLT30"},
	{19, "R_SPARC_COPY"},
	{20, "R_SPARC_GLOB_DAT"},
	{21, "R_SPARC_JMP_SLOT"},
	{22, "R_SPARC_RELATIVE"},
	{23, "R_SPARC_UA32"},
	{24, "R_SPARC_PLT32"},
	{25, "R_SPARC_HIPLT22"},
	{26, "R_SPARC_LOPLT10"},
	{27, "R_SPARC_PCPLT32"},
	{28, "R_SPARC_PCPLT22"},
	{29, "R_SPARC_PCPLT10"},
	{30, "R_SPARC_10"},
	{31, "R_SPARC_11"},
	{32, "R_SPARC_64"},
	{33, "R_SPARC_OLO10"},
	{34, "R_SPARC_HH22"},
	{35, "R_SPARC_HM10"},
	{36, "R_SPARC_LM22"},
	{37, "R_SPARC_PC_HH22"},
	{38, "R_SPARC_PC_HM10"},
	{39, "R_SPARC_PC_LM22"},
	{40, "R_SPARC_WDISP16"},
	{41, "R_SPARC_WDISP19"},
	{42, "R_SPARC_GLOB_JMP"},
	{43, "R_SPARC_7"},
	{44, "R_SPARC_5"},
	{45, "R_SPARC_6"},
	{46, "R_SPARC_DISP64"},
	{47, "R_SPARC_PLT64"},
	{48, "R_SPARC_HIX22"},
	{49, "R_SPARC_LOX10"},
	{50, "R_SPARC_H44"},
	{51, "R_SPARC_M44"},
	{52, "R_SPARC_L44"},
	{53, "R_SPARC_REGISTER"},
	{54, "R_SPARC_UA64"},
	{55, "R_SPARC_UA16"},
}

func (i R_SPARC) String() string   { return stringify(uint32(i), rsparcStrings, false) }
func (i R_SPARC) GoString() string { return stringify(uint32(i), rsparcStrings, true) }

// Magic number for the elf trampoline, chosen wisely to be an immediate value.
const ARM_MAGIC_TRAMP_NUMBER = 0x5c000003
