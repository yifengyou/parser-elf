package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
	fmt.Println("Section Headers:")
	fmt.Println(`  [Nr] Name                     Type            Address          Off    Size   ES Flg                      Lk Inf Al`)
	switch p.F.Ident.Class {
	case ELFCLASS32:
		shstrtab, err := p.F.Sections32[p.F.Header32.Shstrndx].Data()
		if err != nil {
			panic("error reading the section header strings table " + err.Error())
		}
		for index, sh := range p.F.SectionHeaders32 {
			SectionName, ok := getString(shstrtab, int(sh.Name))
			if !ok {
				panic("failed to parse string table")
			}

			fmt.Printf("  [%2d] %-24s %-15d %-.16x %-.6x %-.6x %-.2x %-3x %-2d %-3d %-2d %s\n",
				index, SectionName, sh.Type, sh.Addr, sh.Off, sh.Size, sh.EntSize, sh.Flags, sh.Link, sh.Info, sh.AddrAlign)
		}
	case ELFCLASS64:
		shstrtab, err := p.F.Sections64[p.F.Header64.Shstrndx].Data()
		if err != nil {
			panic("error reading the section header strings table " + err.Error())
		}
		for index, sh := range p.F.SectionHeaders64 {
			SectionName, ok := getString(shstrtab, int(sh.Name))
			if !ok {
				panic("failed to parse string table")
			}

			fmt.Printf("  [%2d] %-24s %-15s %-.16x %-.6x %-.6x %-.2x %-24s %-2d %-3d %-2d\n",
				index, SectionName, SectionType(sh.Type).String(), sh.Addr, sh.Off, sh.Size, sh.EntSize, SectionFlag(sh.Flags).String(), sh.Link, sh.Info, sh.AddrAlign)
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

/*
[root@rockylinux-ebpf ~/parser-elf/src/go]# readelf -lW ls

Elf file type is DYN (Shared object file)
Entry point 0x5e50
There are 11 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x000268 0x000268 R   0x8
  INTERP         0x0002a8 0x00000000000002a8 0x00000000000002a8 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x01fa20 0x01fa20 R E 0x200000
  LOAD           0x01ff70 0x000000000021ff70 0x000000000021ff70 0x0012d8 0x002588 RW  0x200000
  DYNAMIC        0x0209d8 0x00000000002209d8 0x00000000002209d8 0x000210 0x000210 RW  0x8
  NOTE           0x0002c8 0x00000000000002c8 0x00000000000002c8 0x000020 0x000020 R   0x8
  NOTE           0x0002e8 0x00000000000002e8 0x00000000000002e8 0x000044 0x000044 R   0x4
  GNU_PROPERTY   0x0002c8 0x00000000000002c8 0x00000000000002c8 0x000020 0x000020 R   0x8
  GNU_EH_FRAME   0x01c154 0x000000000001c154 0x000000000001c154 0x00090c 0x00090c R   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x01ff70 0x000000000021ff70 0x000000000021ff70 0x001090 0x001090 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.property .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.sec .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .data.rel.ro .dynamic .got .data .bss
   04     .dynamic
   05     .note.gnu.property
   06     .note.ABI-tag .note.gnu.build-id
   07     .note.gnu.property
   08     .eh_frame_hdr
   09
   10     .init_array .fini_array .data.rel.ro .dynamic .got
*/
func (p *Parser) DumpProgramHeaders() {
	PrintSeparator()
	fmt.Println("Program Headers:")
	fmt.Println("  Type               Offset     VirtAddr           PhysAddr           FileSiz    MemSiz     Flg        Align")
	switch p.F.Ident.Class {
	case ELFCLASS32:
		for _, ph := range p.F.ProgramHeaders32 {
			fmt.Printf("  %-18s 0x%.8x 0x%.16x 0x%.16x 0x%.8x 0x%.8x %-10s 0x%x \n",
				ProgType(ph.Type).String(), ph.Off, ph.Vaddr, ph.Paddr, ph.Filesz, ph.Memsz, ProgFlag(ph.Flags).String(), ph.Align)
		}
	case ELFCLASS64:
		for _, ph := range p.F.ProgramHeaders64 {
			fmt.Printf("  %-18s 0x%.8x 0x%.16x 0x%.16x 0x%.8x 0x%.8x %-10s 0x%x \n",
				ProgType(ph.Type).String(), ph.Off, ph.Vaddr, ph.Paddr, ph.Filesz, ph.Memsz, ProgFlag(ph.Flags).String(), ph.Align)
		}
	default:
		fmt.Println("Unkown type")
	}
	fmt.Println(`
 Section to Segment mapping:
  Segment Sections...`)
	// 映射关系参考: <https://stackoverflow.com/questions/23018496/where-is-the-section-to-segment-mapping-stored-in-elf-files>
	switch p.F.Ident.Class {
	case ELFCLASS32:
		shstrtab, err := p.F.Sections32[p.F.Header32.Shstrndx].Data()
		if err != nil {
			panic("error reading the section header strings table " + err.Error())
		}
		for index, ph := range p.F.ProgramHeaders32 {
			phBeginAddr := ph.Vaddr
			phEndAddr := ph.Vaddr + ph.Memsz
			sectionInProgram := ""
			for _, sh := range p.F.SectionHeaders32 {
				// 夹逼准则，左闭右开
				if phBeginAddr <= sh.Addr && sh.Addr < phEndAddr {
					SectionName, ok := getString(shstrtab, int(sh.Name))
					if !ok {
						panic("failed to parse string table")
					}
					sectionInProgram += SectionName + " "
				}
			}
			fmt.Printf("  %.2d %s \n", index, sectionInProgram)
		}
	case ELFCLASS64:
		shstrtab, err := p.F.Sections64[p.F.Header64.Shstrndx].Data()
		if err != nil {
			panic("error reading the section header strings table " + err.Error())
		}
		for index, ph := range p.F.ProgramHeaders64 {
			phBeginAddr := ph.Vaddr
			phEndAddr := ph.Vaddr + ph.Memsz
			sectionInProgram := ""
			for _, sh := range p.F.SectionHeaders64 {
				// 夹逼准则，左闭右开
				if phBeginAddr <= sh.Addr && sh.Addr < phEndAddr {
					SectionName, ok := getString(shstrtab, int(sh.Name))
					if !ok {
						panic("failed to parse string table")
					}
					sectionInProgram += SectionName + " "
				}
			}
			fmt.Printf("  %.2d %s \n", index, sectionInProgram)
		}
	default:
		fmt.Println("Unkown type")
	}
}

/*
[root@rockylinux-ebpf ~/parser-elf/src/go]# readelf -dW ls

Dynamic section at offset 0x209d8 contains 29 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libselinux.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libcap.so.2]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x3588
 0x000000000000000d (FINI)               0x16fd4
 0x0000000000000019 (INIT_ARRAY)         0x21ff70
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x21ff78
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x330
 0x0000000000000005 (STRTAB)             0x1028
 0x0000000000000006 (SYMTAB)             0x380
 0x000000000000000a (STRSZ)              1538 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x220be8
 0x0000000000000002 (PLTRELSZ)           2688 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x2b08
 0x0000000000000007 (RELA)               0x17b8
 0x0000000000000008 (RELASZ)             4944 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x0000000000000018 (BIND_NOW)
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 0x000000006ffffffe (VERNEED)            0x1738
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x162a
 0x000000006ffffff9 (RELACOUNT)          193
 0x0000000000000000 (NULL)               0x0
*/
func (p *Parser) DumpDynamicSection() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		for _, ph := range p.F.ProgramHeaders32 {
			fmt.Printf("  %-18s 0x%.8x 0x%.16x 0x%.16x 0x%.8x 0x%.8x %-10s 0x%x \n",
				ProgType(ph.Type).String(), ph.Off, ph.Vaddr, ph.Paddr, ph.Filesz, ph.Memsz, ProgFlag(ph.Flags).String(), ph.Align)
		}
	case ELFCLASS64:
		sc := p.F.Get64SectionByType(SHT_DYNAMIC)
		if sc == nil {
			fmt.Println("No dynamic section found!")
			return
		}
		//fmt.Printf("%#v\n", sc)
		// DT_NULL Marks the end of the _DYNAMIC array. 只有遇到DT_NULL才算是数据结束，因此entries数值需要遍历一遍得出
		// https://stackoverflow.com/questions/48214977/how-to-find-the-number-of-entries-in-the-dynamic-section-of-an-elf-file
		// https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
		data, err := sc.Data()
		if err != nil {
			panic("cannot load symbol section")
		}
		dynamictable := bytes.NewReader(data)
		dynamics := make([]ELF64DynamicTableEntry, sc.Size/sc.EntSize)
		var dyn ELF64DynamicTableEntry
		binary.Read(dynamictable, p.F.ByteOrder(), &dyn)
		num := 0
		for DT_NULL != DynTag(dyn.Tag) {
			dynamics[num] = ELF64DynamicTableEntry{
				Tag: dyn.Tag,
				Val: dyn.Val,
			}
			num++
			binary.Read(dynamictable, p.F.ByteOrder(), &dyn)
		}
		fmt.Printf("Dynamic section at offset 0x%x contains %d entries:\n", sc.Addr, num+1)
		fmt.Println("  Tag            Type                         Name/Value")
		var strTableAddr uint64
		for _, dyentry := range dynamics {
			if DynTag(dyentry.Tag) == DT_STRTAB {
				strTableAddr = dyentry.Val
			}
		}
		_ = strTableAddr
		for _, dynentry := range dynamics {
			if DynTag(dynentry.Tag) == DT_NEEDED {
				strTableAddr = 0
				//str := ""
				//binary.Read(strTableAddr, p.F.ByteOrder(), &str)
				fmt.Printf("%-.16x %-28s %s\n", dynentry.Tag, DynTag(dynentry.Tag).String())
			} else {
				fmt.Printf("%-.16x %-28s 0x%.16x\n", dynentry.Tag, DynTag(dynentry.Tag).String(), dynentry.Val)
			}
		}
		// DT_NEEDED： 表示一个列表，列表里面以（NEEDED）为标志的项，就是当前库加载时要依赖的其它库。注意 DT_NEEDED 中的 DT 不是 DON'T 的意思。
		// DT_NEEDED 字段的含义依据于链接命令：如果该库以绝对路径链接，那么存储全路径;- 否则存储库名称(或者soname，如果soname被设置)
		//   DT_NEEDED 这个元素保存着以NULL结尾的字符串表的偏移量，那些字符串是所需库的名字。
		//    该偏移量是以DT_STRTAB  为入口的表的索引。看“Shared  Object  Dependencies”
		//    关于那些名字的更多信息。动态数组可能包含了多个这个类型的入口。那些
		//    入口的相关顺序是重要的，虽然它们跟其他入口的关系是不重要的。
	default:
		fmt.Println("Unkown type")
	}
}

/*

符号表默认打印动态符号.dynsym和标准符号.symtab
[root@rockylinux-ebpf ~/parser-elf/example]# readelf --syms -W gcc-amd64-linux-exec

Symbol table '.dynsym' contains 4 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     2: 0000000000000000   396 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     3: 0000000000000000   450 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)

Symbol table '.symtab' contains 74 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000400200     0 SECTION LOCAL  DEFAULT    1
     2: 000000000040021c     0 SECTION LOCAL  DEFAULT    2
     3: 0000000000400240     0 SECTION LOCAL  DEFAULT    3
    70: 00000000006008a0     0 NOTYPE  GLOBAL DEFAULT  ABS _end
    71: 0000000000600898     0 NOTYPE  GLOBAL DEFAULT  ABS _edata
    72: 0000000000400498    27 FUNC    GLOBAL DEFAULT   13 main
    73: 0000000000400398     0 FUNC    GLOBAL DEFAULT   11 _init


*/
func (p *Parser) DumpSymbolTable() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		fmt.Printf("Symbol table '.dynsym' contains %d entries:\n", len(p.F.Symbols32))
		fmt.Println("   Num:    Value           Size        Type          Bind           Vis            Ndx            Name")
		for index, sym := range p.F.Symbols32 {
			if p.F.NamedSymbols[index].Version != "" {
				fmt.Printf("%6d:    %.14x  %-11d %-13s %-14s %-14s %-14s %s@%s %s\n",
					index,
					sym.Value,
					sym.Size,
					SymType(ST_TYPE(sym.Info)).ShortString(),
					SymBind(ST_BIND(sym.Info)).ShortString(),
					ST_VISIBILITY(sym.Info).ShortString(),
					SectionIndex(sym.Shndx).ShortString(),
					p.F.NamedSymbols[index].Name,
					p.F.NamedSymbols[index].Version,
					p.F.NamedSymbols[index].Library,
				)
			} else {
				fmt.Printf("%6d:    %.14x  %-11d %-13s %-14s %-14s %-14s %s\n",
					index,
					sym.Value,
					sym.Size,
					SymType(ST_TYPE(sym.Info)).ShortString(),
					SymBind(ST_BIND(sym.Info)).ShortString(),
					ST_VISIBILITY(sym.Info).ShortString(),
					SectionIndex(sym.Shndx).ShortString(),
					p.F.NamedSymbols[index].Name,
				)
			}
		}
	case ELFCLASS64:
		fmt.Printf("Symbol table '.dynsym' contains %d entries:\n", len(p.F.Symbols64))
		fmt.Println("   Num:    Value           Size        Type          Bind           Vis            Ndx            Name")
		for index, sym := range p.F.Symbols64 {
			if p.F.NamedSymbols[index].Version != "" {
				fmt.Printf("%6d:    %.14x  %-11d %-13s %-14s %-14s %-14s %s@%s %s\n",
					index,
					sym.Value,
					sym.Size,
					SymType(ST_TYPE(sym.Info)).ShortString(),
					SymBind(ST_BIND(sym.Info)).ShortString(),
					ST_VISIBILITY(sym.Info).ShortString(),
					SectionIndex(sym.Shndx).ShortString(),
					p.F.NamedSymbols[index].Name,
					p.F.NamedSymbols[index].Version,
					p.F.NamedSymbols[index].Library,
				)
			} else {
				fmt.Printf("%6d:    %.14x  %-11d %-13s %-14s %-14s %-14s %s\n",
					index,
					sym.Value,
					sym.Size,
					SymType(ST_TYPE(sym.Info)).ShortString(),
					SymBind(ST_BIND(sym.Info)).ShortString(),
					ST_VISIBILITY(sym.Info).ShortString(),
					SectionIndex(sym.Shndx).ShortString(),
					p.F.NamedSymbols[index].Name,
				)
			}
		}
	}
}

func (p *Parser) DumpRelaDynSection() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		p.DumpRelaDynSection32()
	case ELFCLASS64:
		p.DumpRelaDynSection64()
	}
}

func (p *Parser) DumpRelaDynSection32() {

}

/*
[root@rockylinux-ebpf ~/parser-elf/src/go]# readelf -rW ls

Relocation section '.rela.dyn' at offset 0x17b8 contains 206 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend

000000000021ff78  0000000000000008 R_X86_64_RELATIVE                         5ef0
0000000000221240  0000000000000008 R_X86_64_RELATIVE                         163e0
0000000000220f80  0000000800000006 R_X86_64_GLOB_DAT      0000000000000000 free@GLIBC_2.2.5 + 0
0000000000220f88  0000000c00000006 R_X86_64_GLOB_DAT      0000000000000000 _ITM_deregisterTMCloneTable + 0
0000000000220fd0  0000007500000006 R_X86_64_GLOB_DAT      0000000000000000 program_invocation_short_name@GLIBC_2.2.5 + 0
0000000000220fd8  0000007700000006 R_X86_64_GLOB_DAT      0000000000000000 __cxa_finalize@GLIBC_2.2.5 + 0
0000000000220fe0  0000007b00000006 R_X86_64_GLOB_DAT      0000000000000000 stderr@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x2b08 contains 112 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000220c00  0000000100000007 R_X86_64_JUMP_SLOT     0000000000000000 __ctype_toupper_loc@GLIBC_2.3 + 0
0000000000220d80  0000003500000007 R_X86_64_JUMP_SLOT     0000000000000000 memset@GLIBC_2.2.5 + 0
0000000000220f60  0000007800000007 R_X86_64_JUMP_SLOT     0000000000000000 sigaddset@GLIBC_2.2.5 + 0
0000000000220f68  0000007900000007 R_X86_64_JUMP_SLOT     0000000000000000 __ctype_tolower_loc@GLIBC_2.3 + 0
0000000000220f70  0000007a00000007 R_X86_64_JUMP_SLOT     0000000000000000 __ctype_b_loc@GLIBC_2.3 + 0
0000000000220f78  0000007c00000007 R_X86_64_JUMP_SLOT     0000000000000000 __sprintf_chk@GLIBC_2.3.4 + 0
*/
func (p *Parser) DumpRelaDynSection64() {
	sectionHeader := p.F.Get64SectionByName(".rela.dyn")
	//fmt.Printf("%s\n", sectionHeader.HexDumpData())
	//sectionData, err := sectionHeader.Data()
	//if err != nil {
	//	fmt.Printf(err.Error())
	//}

	entryNum := sectionHeader.Size / sectionHeader.EntSize
	fmt.Printf("Relocation section '.rela.dyn' at offset 0x%x contains %d entries:\n", sectionHeader.Off, entryNum)
	// 数据结构
	//type Rela64 struct {
	//	Off    uint64 // Location to be relocated.
	//	Info   uint64 // Relocation type and symbol index.
	//	Addend int64  // Addend.
	//}
	//
	dataRela64 := make([]Rela64, entryNum)
	for i := 0; uint64(i) < entryNum; i++ {
		offset := int64(sectionHeader.Off) + int64(i)*int64(sectionHeader.EntSize)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			panic(err.Error())
		}
		var sh Rela64
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			panic(err.Error())
		}
		dataRela64[i] = sh
	}
	fmt.Println("    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend")
	for index, entry := range dataRela64 {
		// 000000000021ff70  0000000000000008 R_X86_64_RELATIVE                         5f30
		fmt.Printf("%.16x %.16x %s %x [%d]\n", entry.Off, entry.Info, ReloType(R_TYPE64(entry.Info)).String(), entry.Addend, index+1)
	}
}

func (p *Parser) DumpRelaPltSection() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		p.DumpRelaPltSection32()
	case ELFCLASS64:
		p.DumpRelaPltSection64()
	}
}
func (p *Parser) DumpRelaPltSection32() {

}

func (p *Parser) DumpRelaPltSection64() {
	sectionHeader := p.F.Get64SectionByName(".rela.plt")
	//fmt.Printf("%s\n", sectionHeader.HexDumpData())
	//sectionData, err := sectionHeader.Data()
	//if err != nil {
	//	fmt.Printf(err.Error())
	//}
	//
	//
	entryNum := sectionHeader.Size / sectionHeader.EntSize
	fmt.Printf(" Relocation section '.rela.plt' at offset 0x%x contains %d entries:\n", sectionHeader.Off, entryNum)
	// 数据结构
	//type Rela64 struct {
	//	Off    uint64 // Location to be relocated.
	//	Info   uint64 // Relocation type and symbol index.
	//	Addend int64  // Addend.
	//}
	//
	dataRela64 := make([]Rela64, entryNum)
	for i := 0; uint64(i) < entryNum; i++ {
		offset := int64(sectionHeader.Off) + int64(i)*int64(sectionHeader.EntSize)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			panic(err.Error())
		}
		var sh Rela64
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			panic(err.Error())
		}
		dataRela64[i] = sh
	}
	fmt.Println("    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend")
	for index, entry := range dataRela64 {
		// 000000000021ff70  0000000000000008 R_X86_64_RELATIVE                         5f30
		fmt.Printf("%.16x %.16x %-21s   %.16x %x  [%d]\n", entry.Off, entry.Info, ReloType(R_TYPE64(entry.Info)).String(), 0, entry.Addend, index+1)
	}
}

func (p *Parser) DumpGotSection() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		p.DumpGotSection32()
	case ELFCLASS64:
		p.DumpGotSection64()
	}
}
func (p *Parser) DumpGotSection32() {
	sectionHeader := p.F.Get32SectionByName(".got")
	entryNum := sectionHeader.Size / sectionHeader.EntSize
	fmt.Printf(" Relocation section '.got' at offset 0x%x contains %d entries:\n", sectionHeader.Off, entryNum)
	dataRela32 := make([]uint32, entryNum)
	for i := 0; uint32(i) < entryNum; i++ {
		offset := int32(sectionHeader.Off) + int32(i)*int32(sectionHeader.EntSize)
		_, err := p.fs.Seek(int64(offset), io.SeekStart)
		if err != nil {
			panic(err.Error())
		}
		var sh uint32
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			panic(err.Error())
		}
		dataRela32[i] = sh
	}
	fmt.Println("    Value")
	for index, entry := range dataRela32 {
		// 000000000021ff70  0000000000000008 R_X86_64_RELATIVE                         5f30
		fmt.Printf("%.8x[%d]\n", entry, index+1)
	}
}

func (p *Parser) DumpGotSection64() {
	sectionHeader := p.F.Get64SectionByName(".got")
	entryNum := sectionHeader.Size / sectionHeader.EntSize
	fmt.Printf(" Got section '.got' at offset 0x%x contains %d entries:\n", sectionHeader.Off, entryNum)
	dataRela64 := make([]uint64, entryNum)
	for i := 0; uint64(i) < entryNum; i++ {
		offset := int64(sectionHeader.Off) + int64(i)*int64(sectionHeader.EntSize)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			panic(err.Error())
		}
		var sh uint64
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			panic(err.Error())
		}
		dataRela64[i] = sh
	}
	fmt.Println("    Value")
	for index, entry := range dataRela64 {
		// 000000000021ff70  0000000000000008 R_X86_64_RELATIVE                         5f30
		switch index {
		case 0:
			fmt.Printf("[%d] 0x%.16x (address of .dynamic section)\n", index+1, entry)
		case 1:
			fmt.Printf("[%d] 0x%.16x (address of link_map object)\n", index+1, entry)
		case 2:
			fmt.Printf("[%d] 0x%.16x (address of _dl_runtime_resolve function)\n", index+1, entry)
		default:
			fmt.Printf("[%d] 0x%.16x\n", index+1, entry)

		}
	}
}


// .got Section 存放外部全局变量的 GOT 表，非延迟绑定
// .got.plt Section 存放外部函数的 GOT 表，例如 printf，采用延迟绑定

func (p *Parser) DumpGotPltSection() {
	PrintSeparator()
	switch p.F.Ident.Class {
	case ELFCLASS32:
		p.DumpGotPltSection32()
	case ELFCLASS64:
		p.DumpGotPltSection64()
	}
}
func (p *Parser) DumpGotPltSection32() {

}

func (p *Parser) DumpGotPltSection64() {
	sectionHeader := p.F.Get64SectionByName(".got.plt")
	if nil == sectionHeader {
		fmt.Println("No .git.plt section found!")
		return
	}
	entryNum := sectionHeader.Size / sectionHeader.EntSize
	fmt.Printf(" Got section '.got.plt' at offset 0x%x contains %d entries:\n", sectionHeader.Off, entryNum)
	dataRela64 := make([]uint64, entryNum)
	for i := 0; uint64(i) < entryNum; i++ {
		offset := int64(sectionHeader.Off) + int64(i)*int64(sectionHeader.EntSize)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			panic(err.Error())
		}
		var sh uint64
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			panic(err.Error())
		}
		dataRela64[i] = sh
	}
	fmt.Println("    Value")
	for index, entry := range dataRela64 {
		switch index {
		case 0:
			fmt.Printf("[%d] 0x%.16x (address of .dynamic section)\n", index+1, entry)
		case 1:
			fmt.Printf("[%d] 0x%.16x (address of link_map object)\n", index+1, entry)
		case 2:
			fmt.Printf("[%d] 0x%.16x (address of _dl_runtime_resolve function)\n", index+1, entry)
		default:
			fmt.Printf("[%d] 0x%.16x\n", index+1, entry)

		}
	}
}
