package elf

import (
	"encoding/binary"
	"errors"
)

// FileIdent is a representation of the raw ident array (first 16 bytes of an ELF file)
type FileIdent struct {
	// Ident array
	Magic      Magic            `json:"magic"`
	Class      Class            `json:"class"`
	Data       Data             `json:"data"`
	Version    Version          `json:"version"`
	OSABI      OSABI            `json:"os_abi"`
	ABIVersion ABIVersion       `json:"abi_version"`
	ByteOrder  binary.ByteOrder `json:"byte_order"`
}

// FileHeader is an in-memory representation of the raw elf header.
type FileHeader struct {
	Ident FileIdent
	// ELF Header fields
	Type                   Type    `json:"type"` // object file type
	Machine                Machine `json:"machine"`
	Version                Version `json:"version"`
	Entry                  uint64  `json:"entrypoint"`
	ProgramHeaderOffset    uint64  `json:"program_headers_offset"`
	SectionHeaderOffset    uint64  `json:"section_headers_offset"`
	Flags                  uint32  `json:"processor_flag"`
	Size                   uint16  `json:"header_size"`
	ProgramHeaderEntrySize uint16  `json:"ph_entry_size"`
	ProgramHeaderNum       uint16  `json:"ph_entry_num"`
	SectionHeaderEntrySize uint16  `json:"sh_entry_size"`
	SectionHeaderNum       uint16  `json:"sh_entry_num"`
	SectionHeaderStringIdx uint16  `json:"sh_str_idx"`
}

// A Symbol represents an entry in an ELF symbol table section.
type Symbol struct {
	Name  string       `json:"symbol_name"`
	Info  byte         `json:"symbol_info"`
	Other byte         `json:"symbol_other"`
	Index SectionIndex `json:"symbol_index"`
	Value uint64       `json:"symbol_value"`
	Size  uint64       `json:"symbol_size"`
	// Version and Library are present only for the dynamic symbol
	// table.
	Version string `json:"symbol_version"`
	Library string `json:"symbol_library"`
}

// ELFSymbols represents all symbol data.
type ELFSymbols struct {
	NamedSymbols  []Symbol     `json:",omitempty"`
	GNUVersion    []GNUVersion `json:",omitempty"`
	GNUVersionSym []byte       `json:",omitempty"`
}

// File is an in-memory iterable representation of a raw elf binary.
// this is merely used to ease the use of the package as a library
// and allow feature modification and rebuilding of ELF files.
type File struct {
	FileHeader `json:",omitempty"`
	ELFBin32   `json:",omitempty"`
	ELFBin64   `json:",omitempty"`
	ELFSymbols `json:",omitempty"`
}

func NewBinaryFile() *File {
	return &File{}
}

// Class returns ELFClass of the binary (designates the target architecture of the binary x64 or x86)
func (f *File) Class() Class {
	return f.Ident.Class
}

// ByteOrder returns byte order of the binary.
func (f *File) ByteOrder() binary.ByteOrder {
	return f.Ident.ByteOrder
}

// IsELF64 returns true if the binary was compiled with an x64 architecture target.
func (f *File) IsELF64() bool {
	return f.Ident.Class == ELFCLASS64
}

// SectionNames returns the list of section names
func (f *File) SectionNames() []string {
	if len(f.Sections64) != 0 {
		sectionNames := make([]string, len(f.Sections64))
		for i, s := range f.Sections64 {
			sectionNames[i] = s.SectionName
		}
		return sectionNames
	} else if len(f.Sections32) != 0 {
		sectionNames := make([]string, len(f.Sections64))
		for i, s := range f.Sections32 {
			sectionNames[i] = s.SectionName
		}
		return sectionNames
	}

	return []string{""}
}

// GetSectionByType returns the first section with the given type T (nil otherwise).
// 遍历所有节数据描述符，返回匹配的节。可能存在同类型的节，这里没有做处理呢
func (f *File) GetSectionByType(t SectionType) *ELF64Section {
	// f.Section64 在 parseELFSections64 中解析赋值，后续直接通过f.Section64获取节即可
	for _, s := range f.Sections64 {
		if s.Type == uint32(t) {
			return s
		}
	}
	return nil
}

// stringTable reads and returns the string table given by the
// specified link value.
// 将给定link（节索引）的数据解析为字节数组，返回数据、错误
func (f *File) stringTable(link uint32) ([]byte, error) {
	if link <= 0 || link >= uint32(len(f.Sections64)) {
		return nil, errors.New("section has invalid string table link")
	}
	return f.Sections64[link].Data()
}

// getString extracts a string from an ELF string table.
// 给定开头，从字节数组提取字符串（遇到EOF）
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}
	// 开头已经由start确定，只需要确定结尾，则遍历即可
	for end := start; end < len(section); end++ {
		// 遍历section字节数组，如果遇到EOF则左闭右开结束字符串提取
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

// IsValidELFClass validates the ELF class of the binary.
func IsValidELFClass(c Class) bool {
	switch c {
	case ELFCLASS32:
		return true
	case ELFCLASS64:
		return true
	default:
		return false
	}
}

// IsValidELFClass validates the ELF class of the binary.
func ClassToString(c Class) string {
	switch c {
	case ELFCLASS32:
		return "ELF32 [0x01]"
	case ELFCLASS64:
		return "ELF64 [0x02]"
	default:
		return "Not Supported"
	}
}

// IsValidByteOrder validates the ELF byte order field.
func ByteOrderToString(b Data) string {
	switch b {
	case ELFDATA2LSB:
		return "2's complement, little endian [0x01]"
	case ELFDATA2MSB:
		return "2's complement, big endian [0x02]"
	default:
		return "Not Supported"
	}
}

// IsValidByteOrder validates the ELF byte order field.
func IsValidByteOrder(b Data) bool {
	switch b {
	case ELFDATA2LSB:
		return true
	case ELFDATA2MSB:
		return true
	default:
		return false
	}
}

// IsValidVersion validates against the current default version flag EV_CURRENT.
func IsValidVersion(b Version) bool {
	return b == EV_CURRENT
}

func VersionToString(b Version) string {
	switch b {
	case EV_CURRENT:
		return "1 (current) [0x01]"
	default:
		return "unknown version"
	}
}

// goByteOrder encodes a Data field to a native Go byte order field.
func ByteOrder(b Data) binary.ByteOrder {
	switch b {
	case ELFDATA2LSB:
		return binary.LittleEndian
	case ELFDATA2MSB:
		return binary.BigEndian
	default:
		return binary.LittleEndian
	}
}
