package elf

import (
	"fmt"
)

// DumpJSON marshals the entire binary representation into JSON Format.
func (p *Parser) DumpHeaderIndent() {
	fmt.Println("ELF Header:")
	fmt.Printf("Magic:   ")
	for index, value := range p.F.Ident.Magic {
		if 4 == index {
			fmt.Printf("| ")
		}
		fmt.Printf("%.2x ", value)
	}
	fmt.Println("")
	fmt.Printf("Class:                             %s\n", ClassToString(p.F.Ident.Class))
	fmt.Printf("Data:                              %s\n", ByteOrderToString(p.F.Ident.Data))
	fmt.Printf("Version:                           %s\n", VersionToString(p.F.Ident.Version))
	fmt.Printf("OS/ABI:                            %s\n", p.F.Ident.OSABI.String())
	fmt.Printf("ABI Version:                       %d [0x%.2x]\n", p.F.Ident.ABIVersion, p.F.Ident.ABIVersion)
}

/*

ELF头部一共64（0x40）字节
[root@rockylinux-ebpf ~/parser-elf/src/go]# hexdump ls -C |more
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  50 5e 00 00 00 00 00 00  |..>.....P^......|
00000020  40 00 00 00 00 00 00 00  68 28 02 00 00 00 00 00  |@.......h(......|
00000030  00 00 00 00 40 00 38 00  0b 00 40 00 1f 00 1e 00  |....@.8...@.....|
00000040  06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00  |........@.......|

*/
func (p *Parser) DumpHeaderWithoutIndent() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		fmt.Printf("Type:                              %s\n", Type(p.F.Header32.Type).String())
		fmt.Printf("Machine:                           %s\n", Machine(p.F.Header32.Machine).String())
		fmt.Printf("Version:                           0x%x [0x%.8x]\n", p.F.Header32.Version, p.F.Header32.Version)
		fmt.Printf("Entry point address:               0x%x [0x%.16x]\n", p.F.Header32.Entry, p.F.Header32.Entry)
		fmt.Printf("Start of program headers:          %d (bytes into file) [0x%.16x]\n", p.F.Header32.Phoff, p.F.Header32.Phoff)
		fmt.Printf("Start of section headers:          %d (bytes into file) [0x%.16x]\n", p.F.Header32.Shoff, p.F.Header32.Shoff)
		fmt.Printf("Flags:                             0x%.8x\n", p.F.Header32.Flags)
		fmt.Printf("Size of this header:               %d (bytes) [0x%.4x]\n", p.F.Header32.Ehsize, p.F.Header32.Ehsize)
		fmt.Printf("Size of program headers:           %d (bytes) [0x%.4x]\n", p.F.Header32.Phentsize, p.F.Header32.Phentsize)
		fmt.Printf("Number of program headers:         %d [0x%.4x]\n", p.F.Header32.Phnum, p.F.Header32.Phnum)
		fmt.Printf("Size of section header:            %d (bytes) [0x%.4x]\n", p.F.Header32.Shentsize, p.F.Header32.Shentsize)
		fmt.Printf("Number of section headers:         %d (bytes) [0x%.4x]\n", p.F.Header32.Shnum, p.F.Header32.Shnum)
		fmt.Printf("Section header string table index: %d [0x%.4x]\n", p.F.Header32.Shstrndx, p.F.Header32.Shstrndx)
	case ELFCLASS64:
		fmt.Printf("Type:                              %s\n", Type(p.F.Header64.Type).String())
		fmt.Printf("Machine:                           %s\n", Machine(p.F.Header64.Machine).String())
		fmt.Printf("Version:                           0x%x [0x%.8x]\n", p.F.Header64.Version, p.F.Header64.Version)
		fmt.Printf("Entry point address:               0x%x [0x%.16x]\n", p.F.Header64.Entry, p.F.Header64.Entry)
		fmt.Printf("Start of program headers:          %d (bytes into file) [0x%.16x]\n", p.F.Header64.Phoff, p.F.Header64.Phoff)
		fmt.Printf("Start of section headers:          %d (bytes into file) [0x%.16x]\n", p.F.Header64.Shoff, p.F.Header64.Shoff)
		fmt.Printf("Flags:                             0x%.8x\n", p.F.Header64.Flags)
		fmt.Printf("Size of this header:               %d (bytes) [0x%.4x]\n", p.F.Header64.Ehsize, p.F.Header64.Ehsize)
		fmt.Printf("Size of program headers:           %d (bytes) [0x%.4x]\n", p.F.Header64.Phentsize, p.F.Header64.Phentsize)
		fmt.Printf("Number of program headers:         %d [0x%.4x]\n", p.F.Header64.Phnum, p.F.Header64.Phnum)
		fmt.Printf("Size of section header:            %d (bytes) [0x%.4x]\n", p.F.Header64.Shentsize, p.F.Header64.Shentsize)
		fmt.Printf("Number of section headers:         %d (bytes) [0x%.4x]\n", p.F.Header64.Shnum, p.F.Header64.Shnum)
		fmt.Printf("Section header string table index: %d [0x%.4x]\n", p.F.Header64.Shstrndx, p.F.Header64.Shstrndx)
	default:
		fmt.Printf("Type:                              %s\n", "Unkown type")
	}
}

/*
Start of section headers:          141416 (bytes into file) [0x0000000000022868]
Size of section header:            64 (bytes) [0x0040]
Number of section headers:         31 (bytes) [0x001f]
Section header string table index: 30 [0x001e]

There are 31 section headers, starting at offset 0x22868:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000000000002a8 0002a8 00001c 00   A  0   0  1
  [ 2] .note.gnu.property NOTE            00000000000002c8 0002c8 000020 00   A  0   0  8
  [ 3] .note.ABI-tag     NOTE            00000000000002e8 0002e8 000020 00   A  0   0  4
  [ 4] .note.gnu.build-id NOTE            0000000000000308 000308 000024 00   A  0   0  4
  [ 5] .gnu.hash         GNU_HASH        0000000000000330 000330 00004c 00   A  6   0  8
  [ 6] .dynsym           DYNSYM          0000000000000380 000380 000ca8 18   A  7   1  8
  [ 7] .dynstr           STRTAB          0000000000001028 001028 000602 00   A  0   0  1
  [ 8] .gnu.version      VERSYM          000000000000162a 00162a 00010e 02   A  6   0  2
  [ 9] .gnu.version_r    VERNEED         0000000000001738 001738 000080 00   A  7   1  8
  [10] .rela.dyn         RELA            00000000000017b8 0017b8 001350 18   A  6   0  8
  [11] .rela.plt         RELA            0000000000002b08 002b08 000a80 18  AI  6  24  8
  [12] .init             PROGBITS        0000000000003588 003588 00001b 00  AX  0   0  4
  [13] .plt              PROGBITS        00000000000035b0 0035b0 000710 10  AX  0   0 16
  [14] .plt.sec          PROGBITS        0000000000003cc0 003cc0 000700 10  AX  0   0 16
  [15] .text             PROGBITS        00000000000043c0 0043c0 012c12 00  AX  0   0 16
  [16] .fini             PROGBITS        0000000000016fd4 016fd4 00000d 00  AX  0   0  4
  [17] .rodata           PROGBITS        0000000000017000 017000 005151 00   A  0   0 32
  [18] .eh_frame_hdr     PROGBITS        000000000001c154 01c154 00090c 00   A  0   0  4
  [19] .eh_frame         PROGBITS        000000000001ca60 01ca60 002fc0 00   A  0   0  8
  [20] .init_array       INIT_ARRAY      000000000021ff70 01ff70 000008 08  WA  0   0  8
  [21] .fini_array       FINI_ARRAY      000000000021ff78 01ff78 000008 08  WA  0   0  8
  [22] .data.rel.ro      PROGBITS        000000000021ff80 01ff80 000a58 00  WA  0   0 32
  [23] .dynamic          DYNAMIC         00000000002209d8 0209d8 000210 10  WA  7   0  8
  [24] .got              PROGBITS        0000000000220be8 020be8 000400 08  WA  0   0  8
  [25] .data             PROGBITS        0000000000221000 021000 000248 00  WA  0   0 32
  [26] .bss              NOBITS          0000000000221260 021248 001298 00  WA  0   0 32
  [27] .gnu.build.attributes NOTE            00000000006224f8 021248 0005b8 00      0   0  4
  [28] .gnu_debuglink    PROGBITS        0000000000000000 021800 000020 00      0   0  4
  [29] .gnu_debugdata    PROGBITS        0000000000000000 021820 000f04 00      0   0  1
  [30] .shstrtab         STRTAB          0000000000000000 022724 00013e 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
*/
func (p *Parser) DumpSectionHeaders() {
	PrintSeparator()
	fmt.Println(`  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al 字符解析`)
	switch p.F.Ident.Class {
	case ELFCLASS32:
		for index, sh := range p.F.SectionHeaders32 {
			fmt.Printf("  [%2d] %-17d %-15d %-.16x %-.6x %-.6x %-.2x %-3x %-2d %-2d %-2d\n",
				index, sh.Name, sh.Type, sh.Addr, sh.Off, sh.Size, sh.EntSize, sh.Flags, sh.Link, sh.Info, sh.AddrAlign)
		}
	case ELFCLASS64:
		for index, sh := range p.F.SectionHeaders64 {
			fmt.Printf("  [%2d] %-17d %-15d %-.16x %-.6x %-.6x %-.2x %-3x %-2d %-3d %-2d %s\n",
				index, sh.Name, sh.Type, sh.Addr, sh.Off, sh.Size, sh.EntSize, sh.Flags, sh.Link, sh.Info, sh.AddrAlign, string(sh.Name))
		}
	default:
		fmt.Println("Unkown type")
	}
	fmt.Println(`Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)`)
}
