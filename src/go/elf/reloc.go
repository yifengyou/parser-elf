package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Relocation entries.

// ELF32 Relocations that don't need an addend field.
type Rel32 struct {
	Off  uint32 // Location to be relocated.
	Info uint32 // Relocation type and symbol index.
}

// ELF32 Relocations that need an addend field.
type Rela32 struct {
	Off    uint32 // Location to be relocated.
	Info   uint32 // Relocation type and symbol index.
	Addend int32  // Addend.
}

func R_SYM32(info uint32) uint32      { return info >> 8 }
func R_TYPE32(info uint32) uint32     { return info & 0xff }
func R_INFO32(sym, typ uint32) uint32 { return sym<<8 | typ }

// ELF64 relocations that don't need an addend field.
type Rel64 struct {
	Off  uint64 // Location to be relocated.
	Info uint64 // Relocation type and symbol index.
}

// ELF64 relocations that need an addend field.
type Rela64 struct {
	Off    uint64 // Location to be relocated.
	Info   uint64 // Relocation type and symbol index.
	Addend int64  // Addend.
}

func R_SYM64(info uint64) uint32    { return uint32(info >> 32) }
func R_TYPE64(info uint64) uint32   { return uint32(info) }
func R_INFO(sym, typ uint32) uint64 { return uint64(sym)<<32 | uint64(typ) }

type ReloType uint32

var RelaTypeStrings = []flagName{
	{ 0, "R_X86_64_NONE" },
	{ 1, "R_X86_64_64" },
	{ 2, "R_X86_64_PC32" },
	{ 3, "R_X86_64_GOT32" },
	{ 4, "R_X86_64_PLT32" },
	{ 5, "R_X86_64_COPY" },
	{ 6, "R_X86_64_GLOB_DAT" },
	{ 7, "R_X86_64_JUMP_SLOT" },
	{ 8, "R_X86_64_RELATIVE" },
	{ 9, "R_X86_64_GOTPCREL" },
	{ 10, "R_X86_64_32" },
	{ 11, "R_X86_64_32S" },
	{ 12, "R_X86_64_16" },
	{ 13, "R_X86_64_PC16" },
	{ 14, "R_X86_64_8" },
	{ 15, "R_X86_64_PC8" },
	{ 16, "R_X86_64_DTPMOD64" },
	{ 17, "R_X86_64_DTPOFF64" },
	{ 18, "R_X86_64_TPOFF64" },
	{ 19, "R_X86_64_TLSGD" },
	{ 20, "R_X86_64_TLSLD" },
	{ 21, "R_X86_64_DTPOFF32" },
	{ 22, "R_X86_64_GOTTPOFF" },
	{ 23, "R_X86_64_TPOFF32" },
	{ 24, "R_X86_64_PC64" },
	{ 25, "R_X86_64_GOTOFF64" },
	{ 26, "R_X86_64_GOTPC32" },
	{ 27, "R_X86_64_GOT64" },
	{ 28, "R_X86_64_GOTPCREL64" },
	{ 29, "R_X86_64_GOTPC64" },
	{ 30, "R_X86_64_GOTPLT64" },
	{ 31, "R_X86_64_PLTOFF64" },
	{ 32, "R_X86_64_SIZE32" },
	{ 33, "R_X86_64_SIZE64" },
	{ 34, "R_X86_64_GOTPC32_TLSDESC" },
	{ 35, "R_X86_64_TLSDESC_CALL" },
	{ 36, "R_X86_64_TLSDESC" },
	{ 37, "R_X86_64_IRELATIVE" },
	{ 38, "R_X86_64_RELATIVE64" },
	{ 39, "R_X86_64_NUM" },
}

func (rt ReloType) String() string   { return stringify(uint32(rt), RelaTypeStrings, false) }
func (rt ReloType) GoString() string { return stringify(uint32(rt), RelaTypeStrings, true) }

// ApplyRelocations will apply relocations depending on the target binary.
// This step essentially processes symbolic references to their definitions.
func (p *Parser) ApplyRelocations(dst []byte, rels []byte) error {
	switch {
	case p.F.Class() == ELFCLASS64 && p.F.Machine == EM_X86_64:
		return p.applyRelocationsAMD64(dst, rels)
	default:
		return errors.New("not implemented")
	}
}

// applyRelocationsAMD64 applies relocatons to dst where rels is a relocations section
// for AMD64 (64-bit binaries & x86-64 machine types).
func (p *Parser) applyRelocationsAMD64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}
	symbols, _, err := p.getSymbols64(SHT_SYMTAB)
	if err != nil {
		return err
	}
	b := bytes.NewReader(rels)
	var rela Rela64
	for b.Len() > 0 {
		binary.Read(b, p.F.ByteOrder(), &rela)
		symNo := rela.Info >> 32
		t := R_X86_64(rela.Info & 0xffff)
		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]

		// There are relocations, so this must be a normal
		// object file.  The code below handles only basic relocations
		// of the form S + A (symbol plus addend).
		switch t {
		case R_X86_64_64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			p.F.ByteOrder().PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_X86_64_32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			p.F.ByteOrder().PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}
	return nil
}
