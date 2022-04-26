package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/saferwall/binstream"
)

// Parser implements a parsing engine for the ELF file format.
type Parser struct {
	fs binstream.Stream
	F  *File
}

// New creates a new instance of parser.
func New(filename string) (*Parser, error) {
	// 使用saferwall作者另一个库binstream
	// 将文件map到内存，作为字节流
	fs, err := binstream.NewFileStream(filename)
	if err != nil {
		return nil, err
	}
	// Parser结构，将fs字节流内容提取填充到F结构中
	p := &Parser{
		fs: fs,
		F:  &File{},
	}
	return p, nil
}

// NewBytes creates a new instance of parser from a byte slice representig the ELF binary.
func NewBytes(data []byte) (*Parser, error) {
	fs, err := binstream.NewByteStream(data)
	if err != nil {
		return nil, err
	}
	p := &Parser{
		fs: fs,
		F:  &File{},
	}
	return p, nil
}

// Parse will parse the entire ELF file.
func (p *Parser) Parse() error {
	// 解析ELF头部的Indent信息，描述该二进制文件对应的体系结构，包括对应的字长，CPU架构，大小端等
	// Ident解析出的Class用于后面判定ELF32/ELF64用
	err := p.ParseIdent()
	if err != nil {
		return err
	}
	// ELF头中最开头Indent里Class锚定了是ELF32还是ELF64
	elfClass := p.F.Ident.Class
	// 根据class（ELF32/ELF64）使用不同的头解析方法
	err = p.ParseELFHeader(elfClass)
	if err != nil {
		return err
	}
	// 解析所有节头
	err = p.ParseELFSectionHeaders(elfClass)
	if err != nil {
		return err
	}
	// 解析所有节
	err = p.ParseELFSections(elfClass)
	if err != nil {
		return err
	}
	// 解析程序头
	err = p.ParseELFProgramHeaders(elfClass)
	if err != nil {
		return err
	}
	// 解析所有符号表，指定为动态符号SHT_DYNSYM，而非SHT_SYMTAB
	err = p.ParseELFSymbols(elfClass, SHT_DYNSYM)
	if err != nil {
		return err
	}
	return nil
}

/*
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x5e50
  Start of program headers:          64 (bytes into file)
  Start of section headers:          141416 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
*/
// ParseIdent will parse the identification bytes at the start of the ELF File.
func (p *Parser) ParseIdent() error {

	ident := make([]byte, EI_NIDENT)
	// Read the ELF Header E_Ident array.
	// This step helps find out the architecture
	// that the binary targets, as well as OS ABI version
	// and other compilation artefact.
	n, err := p.fs.ReadAt(ident, 0)
	if n != EI_NIDENT || err != nil {
		return err
	}

	if n != 16 || string(ident[:4]) != ELFMAG {
		return errors.New("bad magic number " + string(ident[:4]) + " expected : " + ELFMAG)
	}
	// 因为readelf -h中的magic是给出了前16个字节
	// 实际magic只需要4个字节。选择与readelf一致，对读几个字节，不影响后续解析
	copy(p.F.Ident.Magic[:], ident[:EI_NIDENT])

	if !IsValidELFClass(Class(ident[EI_CLASS])) {
		return errors.New("invalid ELF class")
	}
	if !IsValidByteOrder(Data(ident[EI_DATA])) {
		return errors.New("invalid ELF byte order")
	}
	if !IsValidVersion(Version(ident[EI_VERSION])) {
		return errors.New("bad ELF version")
	}

	p.F.Ident.Class = Class(ident[EI_CLASS])
	p.F.Ident.Data = Data(ident[EI_DATA])
	// 独立开辟一个BtyeOrder用于标记大小端
	p.F.Ident.ByteOrder = ByteOrder(Data(ident[EI_DATA]))
	p.F.Ident.Version = Version(ident[EI_VERSION])
	p.F.Ident.OSABI = OSABI(ident[EI_OSABI])
	p.F.Ident.ABIVersion = ABIVersion(ident[EI_ABIVERSION])

	return nil
}

// CloseFile will close underlying mmap file
func (p *Parser) CloseFile() error {
	return p.fs.Close()
}

// ParseELFHeader reads the raw elf header depending on the ELF Class (32 or 64).
func (p *Parser) ParseELFHeader(c Class) error {

	// Because of parsing ambiguitiy we need parentheses here
	// ref : https://golang.org/ref/spec#Composite_literals
	// The two structs are comparable because all the fields are
	// comparable values https://golang.org/ref/spec#Comparison_operators
	if (FileIdent{} == p.F.Ident) {
		err := p.ParseIdent()
		if err != nil {
			return err
		}
	}
	switch c {
	case ELFCLASS32:
		return p.parseELFHeader32()
	case ELFCLASS64:
		return p.parseELFHeader64()
	default:
		return errors.New("unknown ELF Class")
	}
}

// parseELFHeader32 parses specifically 32-bit built ELF binaries.
func (p *Parser) parseELFHeader32() error {
	hdr := NewELF32Header()
	n, err := p.fs.Seek(0, io.SeekStart)
	if err != nil {
		errString := fmt.Errorf(
			"failed to seek start of stream with error : %v , read %d expected %d",
			err, n, EI_NIDENT,
		)
		return errors.New(errString.Error())
	}
	if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &hdr); err != nil {
		return err
	}
	p.F.Header32 = hdr
	return nil
}

// parseELFHeader64 parses specifically 64-bit built ELF binaries.
func (p *Parser) parseELFHeader64() error {
	hdr := NewELF64Header()
	n, err := p.fs.Seek(0, io.SeekStart)
	if err != nil {
		errString := fmt.Errorf(
			"failed to seek start of stream with error : %v , read %d expected %d",
			err, n, EI_NIDENT,
		)
		return errors.New(errString.Error())
	}
	// ELF 头部大小固定，直接读取即可，不过要注意大小端
	// 32位的ELF header占52个字节，64位的ELF header占64个字节
	if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &hdr); err != nil {
		return err
	}
	// 赋值，hdr其实做了数据拷贝，显然
	p.F.Header64 = hdr
	return nil
}

// ParseELFSectionHeaders reads the raw elf section header.
func (p *Parser) ParseELFSectionHeaders(c Class) error {
	switch c {
	case ELFCLASS32:
		return p.parseELFSectionHeader32()
	case ELFCLASS64:
		return p.parseELFSectionHeader64()
	default:
		return errors.New("unknown ELF class")
	}
}

// parseELFSectionHeader32 parses specifically the raw elf section header of 32-bit binaries.
func (p *Parser) parseELFSectionHeader32() error {
	if p.F.Header32 == NewELF32Header() {
		return errors.New("header need to be parsed first")
	}
	if p.F.Header32.Shnum == 0 || p.F.Header32.Shoff == 0 {
		return errors.New("ELF file doesn't contain any section header table")
	}
	shnum := p.F.Header32.SectionHeadersNum()
	shoff := p.F.Header32.SectionHeadersOffset()
	shentz := p.F.Header32.Shentsize

	names := make([]uint32, shnum)
	sectionHeaders := make([]ELF32SectionHeader, shnum)
	for i := 0; uint16(i) < shnum; i++ {
		// Section index 0, and indices in the range 0xFF00–0xFFFF are reserved for special purposes.
		offset := int64(shoff) + int64(i)*int64(shentz)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			return err
		}
		// section header file offset
		var sh ELF32SectionHeader
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			return err
		}
		names[i] = sh.Name
		sectionHeaders[i] = sh
		p.F.SectionHeaders32 = sectionHeaders
	}
	return nil
}

// parseELFSectionHeader64 parses specifically the raw elf section header of 64-bit binaries.
func (p *Parser) parseELFSectionHeader64() error {
	// 判断ELF64头信息是否解析
	if p.F.Header64 == NewELF64Header() {
		return errors.New("header need to be parsed first")
	}
	// 如果节数量和节偏移都是0，说明节信息不存在
	if p.F.Header64.Shnum == 0 || p.F.Header64.Shoff == 0 {
		return errors.New("ELF file doesn't contain any section header table")
	}
	shnum := p.F.Header64.SectionHeadersNum()    // 节数量
	shoff := p.F.Header64.SectionHeadersOffset() // 所有节头信息所在文件的偏移
	shentz := p.F.Header64.Shentsize             // 每节大小

	names := make([]uint32, shnum)
	sectionHeaders := make([]ELF64SectionHeader, shnum)
	for i := 0; uint16(i) < shnum; i++ {
		// Section index 0, and indices in the range 0xFF00–0xFFFF are reserved for special purposes.
		// 从开头依次读取
		offset := int64(shoff) + int64(i)*int64(shentz)
		// 借用 binstream.Stream 调整游标，置为文件开头 i*sizeof(ELF64SectionHeader)+offset 位置
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			return err
		}
		// section header file offset
		var sh ELF64SectionHeader
		// 读取节头放到ELF64SectionHeader结构中
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			return err
		}
		names[i] = sh.Name
		// 所有的ELF64SectionHeader结构放到sectionHeaders数组中
		sectionHeaders[i] = sh
	}
	// 没必要每次赋值，放到for循环外面
	// p.F.SectionHeaders64存放了所有节头信息，不包括节数据
	p.F.SectionHeaders64 = sectionHeaders
	return nil
}

// ParseELFSections reads the raw elf sections.
// 根据节头信息，继续解析节数据
func (p *Parser) ParseELFSections(c Class) error {
	switch c {
	case ELFCLASS32:
		return p.parseELFSections32()
	case ELFCLASS64:
		return p.parseELFSections64()
	default:
		return errors.New("unknown ELF class")
	}
}

// parseELFSections64 parses all sections in a 64-bit ELF binary.
// 关键函数，解析所有节并放到p.F句柄下
func (p *Parser) parseELFSections64() error {
	// 做sanity check，健全性校验
	// 如果节头数据长度为空，那说明没有任何节数据呀，也可能是没有解析
	// 这里做了尝试，重新解析节头
	if len(p.F.SectionHeaders64) == 0 {
		// 若没有任何节，则重新解析ELF头
		// 没有任何节的ELF没有任何意义
		err := p.parseELFSectionHeader64()
		if err != nil {
			return err
		}
	}
	// 从ELF头获取节数量 len(p.F.SectionHeaders64) 不也可以吗？
	shnum := p.F.Header64.Shnum
	// make创建节数据空间，数组，数量为shnum，每个元素就是一个完整节数据以及节数据的元数据（例如指向节头）
	sections := make([]*ELF64Section, shnum)
	// 遍历所有节头，将节数据放到sections中，每个节构造一个ELF64Section结构
	for i := 0; i < int(shnum); i++ {
		s := &ELF64Section{}
		// 从节头提取数据，节数据大小（字节）。这里记录的是不管压缩没有压缩的大小，静态ELF对应节的大小
		// 后续会根据标志位判断是否压缩过，如果压缩过需要重新计算节数据大小，实际解压后的大小
		size := p.F.SectionHeaders64[i].Size
		// ELF64Section是节数据的元数据，包括了指向对应节头元数据SectionHeaders64的指针
		s.ELF64SectionHeader = p.F.SectionHeaders64[i]
		// 使用内置IO库读取区间数据
		// func NewSectionReader(r ReaderAt, off int64, n int64) *SectionReader
		// 返回的是SectionReader指针，若要获取字节数据，仍然需要调用其方法Read()
		// sr是节数据，不是节头数据，节头已经安排在p.F.SectionHeaders64[]数组中
		// 这里依然是从 fs binstream.Stream 读取内容
		// s.Off 其实是在 s.ELF64SectionHeader 中
		s.sr = io.NewSectionReader(p.fs, int64(s.Off), int64(size))

		// 针对节是否压缩，操作不同
		if s.Flags&uint64(SHF_COMPRESSED) == 0 {
			// 没有压缩过，则节的大小其实就是节头记录的大小
			s.Size = p.F.SectionHeaders64[i].Size
		} else {
			ch := new(ELF64CompressionHeader)
			// 间接调用SectionReader的Read方法
			// 将数据读取到特有的压缩节头中，binary.Read会自动处理大小端和数据解析
			// 如果节是压缩的，那么压缩的元数据会放在节数据的开头
			// 将节数据开头解析为ELF64CompressionHeader结构，其中就包括实际解压后的大小
			err := binary.Read(s.sr, p.F.Ident.ByteOrder, ch)
			if err != nil {
				return errors.New("error reading compressed header " + err.Error())
			}
			s.compressionType = CompressionType(ch.Type)
			s.Size = ch.Size
			s.AddrAlign = ch.AddrAlign
			// 压缩数据的偏移compressionOffset，因为压缩节的元数据在节数据开头
			// 那么部分压缩数据其实可能并非直接排在开头之后
			s.compressionOffset = int64(binary.Size(ch))
		}
		// ELF64Section表示一个完整的节，包括节头(元数据)和节数据
		sections[i] = s
	}
	// 没有任何节，ELF没有意义
	if len(sections) == 0 {
		return errors.New("binary has no sections")
	}
	// 获取节头相关的字符串信息。这个信息也是存放在一个特定的节中的，这个节叫Shstrndx
	// 获取指定节的字符表
	shstrtab, err := sections[p.F.Header64.Shstrndx].Data()
	if err != nil {
		return errors.New("error reading the section header strings table " + err.Error())
	}
	// p.F.SectionHeaders64[i].Name 节头也包含节名称字段，但是其为节名称在字符表的索引，而非实际字符串
	// 节名称字符串需要通过检索字符表获得，最后存放在节数据元数据结构中
	for i, s := range sections {
		var ok bool
		// 遍历所有节，将节头名称赋值为解析过的字符串
		s.SectionName, ok = getString(shstrtab, int(p.F.SectionHeaders64[i].Name))
		if !ok {
			return errors.New("failed to parse string table")
		}
	}
	// 将句柄发到p.F下方便访问，放在每节数据中
	//type ELFBin64 struct {
	//   Header64         ELF64Header
	//   SectionHeaders64 []ELF64SectionHeader // 每节头数据
	//   ProgramHeaders64 []ELF64ProgramHeader
	//   Sections64       []*ELF64Section // 每节数据
	//   Symbols64        []ELF64SymbolTableEntry
	//}
	p.F.Sections64 = sections
	return nil
}

// parseELFSections32 parses all sections in a 32-bit ELF binary.
func (p *Parser) parseELFSections32() error {
	if len(p.F.SectionHeaders32) == 0 {
		err := p.parseELFSectionHeader32()
		if err != nil {
			return err
		}
	}
	shnum := p.F.Header32.Shnum
	sections := make([]*ELF32Section, shnum)

	for i := 0; i < int(shnum); i++ {
		s := &ELF32Section{}
		size := p.F.SectionHeaders32[i].Size
		s.ELF32SectionHeader = p.F.SectionHeaders32[i]
		s.sr = io.NewSectionReader(p.fs, int64(s.Off), int64(size))

		if s.Flags&uint32(SHF_COMPRESSED) == 0 {
			s.Size = p.F.SectionHeaders32[i].Size
		} else {
			ch := new(ELF32CompressionHeader)
			err := binary.Read(s.sr, p.F.Ident.ByteOrder, ch)
			if err != nil {
				return errors.New("error reading compressed header " + err.Error())
			}
			s.compressionType = CompressionType(ch.Type)
			s.Size = ch.Size
			s.AddrAlign = ch.AddrAlign
			s.compressionOffset = int64(binary.Size(ch))
		}
		sections[i] = s
	}
	if len(sections) == 0 {
		return errors.New("binary has no sections")
	}
	shstrtab, err := sections[p.F.Header64.Shstrndx].Data()
	if err != nil {
		return errors.New("error reading the section header strings table " + err.Error())
	}

	for i, s := range sections {
		var ok bool
		s.SectionName, ok = getString(shstrtab, int(p.F.SectionHeaders64[i].Name))
		if !ok {
			return errors.New("failed to parse string table")
		}
	}
	p.F.Sections32 = sections
	return nil
}

// ParseELFProgramHeaders reads the raw elf program header.
func (p *Parser) ParseELFProgramHeaders(c Class) error {

	switch c {
	case ELFCLASS32:
		return p.parseELFProgramHeaders32()
	case ELFCLASS64:
		return p.parseELFProgramHeaders64()
	default:
		return errors.New("unknown ELF class")
	}
}

// parseELFProgramHeaders64 parses all program header table entries in a 64-bit ELF binary.
func (p *Parser) parseELFProgramHeaders64() error {
	// 程序头偏移，在ELF头中
	phOff := p.F.Header64.Phoff
	// 程序头条目，在ELF头中
	phNum := p.F.Header64.Phnum
	// 程序头每条记录大小，在ELF头中
	phEntSize := p.F.Header64.Phentsize
	// 程序头，数组，每个元素都是ELF64ProgramHeader，数量是ELF头记录的数量
	programHeaders := make([]ELF64ProgramHeader, phNum)
	// 遍历程序头，读取程序头放在数组中
	for i := 0; i < int(phNum); i++ {
		off := int64(phOff) + int64(i)*int64(phEntSize)
		// 重置文件游标到off处
		p.fs.Seek(off, io.SeekStart)
		var ph ELF64ProgramHeader
		// binary.Read 仍然跟游标有关，按大小端读取程序头元数据
		err := binary.Read(p.fs, p.F.Ident.ByteOrder, &ph)
		if err != nil {
			return err
		}
		// 每程序头都放在数组中
		programHeaders[i] = ph
	}
	// 所有程序头都放在全局对象中访问
	p.F.ProgramHeaders64 = programHeaders
	return nil
}

// parseELFProgramHeaders32 parses all program header table entries in a 32-bit ELF binary.
func (p *Parser) parseELFProgramHeaders32() error {
	phOff := p.F.Header32.Phoff
	phNum := p.F.Header32.Phnum
	phEntSize := p.F.Header32.Phentsize
	programHeaders := make([]ELF32ProgramHeader, phNum)

	for i := 0; i < int(phNum); i++ {
		off := int64(phOff) + int64(i)*int64(phEntSize)
		p.fs.Seek(off, io.SeekStart)
		var ph ELF32ProgramHeader
		err := binary.Read(p.fs, p.F.Ident.ByteOrder, &ph)
		if err != nil {
			return err
		}
		programHeaders[i] = ph
	}
	p.F.ProgramHeaders32 = programHeaders
	return nil
}

// ParseELFSymbols returns a slice of Symbols from parsing the symbol table
// with the given type, along with the associated string table
// (the null symbol at index 0 is omitted). 忽略0项与readelf不符，因此调整代码再安排上
// 符号表也是在某个节中，毫无疑问，本质也是节的解析
// .dnysym / .symtab
// 动态符号表 (.dynsym) 用来保存与动态链接相关的导入导出符号，不包括模块内部的符号
// 符号表 (.symtab) 保存所有符号; .symtab中包括 .dynsym 中的符号。
// https://zhuanlan.zhihu.com/p/314912277
// https://picture.iczhiku.com/weixin/message1608207112927.html
func (p *Parser) ParseELFSymbols(c Class, typ SectionType) error {
	switch c {
	case ELFCLASS64:
		_, _, err := p.getSymbols64(typ)
		return err
	case ELFCLASS32:
		_, _, err := p.getSymbols32(typ)
		return err
	}
	return errors.New("unknown ELF class")
}

func (p *Parser) getSymbols32(typ SectionType) ([]Symbol, []byte, error) {
	symtabSection := p.F.GetSectionByType(typ)
	if symtabSection == nil {
		return nil, nil, ErrNoSymbols
	}
	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, errors.New("cannot load symbol section")
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%Sym32Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of SymSize")
	}
	strdata, err := p.F.stringTable(symtabSection.Link)
	if err != nil {
		return nil, nil, errors.New("cannot load string table section")
	}
	// The first entry is all zeros.
	var skip [Sym32Size]byte
	symtab.Read(skip[:])
	symbols := make([]ELF32SymbolTableEntry, symtab.Len()/Sym32Size)
	namedSymbols := make([]Symbol, symtab.Len()/Sym32Size)
	i := 0
	var sym ELF32SymbolTableEntry
	for symtab.Len() > 0 {
		binary.Read(symtab, p.F.ByteOrder(), &sym)
		symbols[i] = sym
		str, _ := getString(strdata, int(sym.Name))
		namedSymbols[i] = Symbol{
			Name:    str,
			Info:    sym.Info,
			Other:   sym.Other,
			Index:   SectionIndex(sym.Shndx),
			Value:   uint64(sym.Value),
			Size:    uint64(sym.Size),
			Version: "",
			Library: "",
		}
		i++
	}
	p.F.Symbols32 = symbols
	p.F.NamedSymbols = namedSymbols
	return namedSymbols, strdata, nil
}

// 解析ELF64 符号表
func (p *Parser) getSymbols64(typ SectionType) ([]Symbol, []byte, error) {
	// GetSectionByType是F  *File的方法
	// 遍历所有节数据描述符，获取匹配符号表的节数据描述符
	symtabSection := p.F.GetSectionByType(typ)
	if symtabSection == nil {
		return nil, nil, ErrNoSymbols
	}
	// 获取节数据
	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, errors.New("cannot load symbol section")
	}
	// 使用bytes包对字节数据进行操作
	symtab := bytes.NewReader(data)
	// 如果不能被24除尽，则不是标准的大小；没有对齐
	if symtab.Len()%Sym64Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}
	// 获取符号表对应节的字符表
	// 节头信息中有个link字段，用于表示关联的节
	// .dynsym 关联的节是 .dynstr ，提供字符串
	// stringTable作用是将给定的link（索引）所在节解析为字符串，返回字节数组
	// 获取到对应 .dynstr节的字符串数据
	dynstrStringTable, err := p.F.stringTable(symtabSection.Link)
	if err != nil {
		return nil, nil, errors.New("cannot load string table section")
	}
	// The first entry is all zeros. 原程序选择跳过，修改不跳过，与readelf保持一致
	//var skip [Sym64Size]byte
	//symtab.Read(skip[:])
	// 体系结构相关的符号表数组，每项ELF64SymbolTableEntry
	// .dynsym 节数据其实是有规则的数据，可以拆分成若干条ELF64SymbolTableEntry项
	symbols := make([]ELF64SymbolTableEntry, symtab.Len()/Sym64Size)
	// 体系结构无关的符号数据
	namedSymbols := make([]Symbol, symtab.Len()/Sym64Size)
	i := 0
	var sym ELF64SymbolTableEntry
	for symtab.Len() > 0 {
		binary.Read(symtab, p.F.ByteOrder(), &sym)
		str, _ := getString(dynstrStringTable, int(sym.Name))
		symbols[i] = ELF64SymbolTableEntry{
			Name:  sym.Name,
			Info:  sym.Info,
			Other: sym.Other,
			Shndx: sym.Shndx,
			Value: sym.Value,
			Size:  sym.Size,
		}
		namedSymbols[i] = Symbol{
			Name:    str,
			Info:    sym.Info,
			Other:   sym.Other,
			Index:   SectionIndex(sym.Shndx), // 类型转换为节索引  type SectionIndex int
			Value:   sym.Value,
			Size:    sym.Size,
			Version: "",
			Library: "",
		}
		i++
	}
	// 获取GNU库依赖信息，传递dynstrStringTable
	err = p.ParseGNUVersionTable(dynstrStringTable)
	if err == nil {
		for i := range namedSymbols {
			// p.gnuVersion(i-1) 与上述跳过第一条目保持一致
			namedSymbols[i].Library, namedSymbols[i].Version = p.gnuVersion(i-1)
		}
	}
	// 与体系结构相关的
	p.F.Symbols64 = symbols
	// 符号名称放在与体系结构无关的地方
	p.F.NamedSymbols = namedSymbols
	return namedSymbols, dynstrStringTable, nil
}
