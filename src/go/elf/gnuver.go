// Package elf: gnuver.go implements the GNU Version table specification.
package elf

import "errors"

// GNUVersion holds the version information
type GNUVersion struct {
	File string
	Name string
}

// ImportedSymbol will hold information on external imports.
type ImportedSymbol struct {
	Name    string
	Version string
	Library string
}

// ParseGNUVersionTable parses the GNU version tables.
//.gnu.version(version symbol section)。dynamic table中的DT_VERSYM tag指向该section。
//	假设.dynsym有N个entries，那么.gnu.version包含N个uint16_t。第i个entry描述第i个dynamic symbol table所属的version
//.gnu.version_r(version requirement section)。dynamic table中的DT_VERNEED/DT_VERNEEDNUM tags标记该section。
//	描述该模块的未定义的versioned符号用到的version信息
//.gnu.version_d(version definition section)。dynamic table中的DT_VERDEF/DT_VERDEFNUM tags标记该section。
//	记录该模块定义的versioned符号用到的version信息
// str 是 dynstrStringTable 即.dynstr节数据，字符串数据
func (p *Parser) ParseGNUVersionTable(str []byte) error {
	// sanity check，健全校验
	if p.F.GNUVersion != nil {
		return errors.New("already processed GNU version table")
	}
	// GNU 依赖版本信息存放在.gnu.version_r节中
	// .gnu.version_r 表示二进制程序实际依赖的库文件版本
	// SHT_GNU_VERNEED GNU version needs section
	gnuVersionNeedSection := p.F.GetSectionByType(SHT_GNU_VERNEED)
	if gnuVersionNeedSection == nil {
		return errors.New("no gnu verneed section in file")
	}
	// 获取.gnu.version_r节的数据，这个节数据什么规律？
	// .gnu.version_r节的字符串数据存放在.dynstr节数据中
	gnuVersionNeedSectionData, _ := gnuVersionNeedSection.Data()

	var gnuVer []GNUVersion
	i := 0
	for {
		if i+16 > len(gnuVersionNeedSectionData) {
			break
		}
		vers := p.F.ByteOrder().Uint16(gnuVersionNeedSectionData[i : i+2])
		if vers != 1 {
			break
		}
		cnt := p.F.ByteOrder().Uint16(gnuVersionNeedSectionData[i+2 : i+4])
		fileoff := p.F.ByteOrder().Uint32(gnuVersionNeedSectionData[i+4 : i+8])
		aux := p.F.ByteOrder().Uint32(gnuVersionNeedSectionData[i+8 : i+12])
		next := p.F.ByteOrder().Uint32(gnuVersionNeedSectionData[i+12 : i+16])
		// 从.dynstr字符串节指定偏移中提取string
		file, _ := getString(str, int(fileoff))

		var name string

		j := i + int(aux)
		for c := 0; c < int(cnt); c++ {
			if j+16 > len(gnuVersionNeedSectionData) {
				break
			}
			other := p.F.ByteOrder().Uint16(gnuVersionNeedSectionData[j+6 : j+8])
			nameoff := p.F.ByteOrder().Uint32(gnuVersionNeedSectionData[j+8 : j+12])
			next := p.F.ByteOrder().Uint32(gnuVersionNeedSectionData[j+12 : j+16])
			// 从.dynstr字符串节指定偏移中提取string
			name, _ = getString(str, int(nameoff))
			ndx := int(other)
			if ndx >= len(gnuVer) {
				a := make([]GNUVersion, 2*(ndx+1))
				copy(a, gnuVer)
				gnuVer = a
			}
			gnuVer[ndx] = GNUVersion{file, name}
			if next == 0 {
				break
			}
			j += int(next)
		}
		if next == 0 {
			break
		}
		i += int(next)

	}
	// Versym parallels symbol table, indexing into verneed.
	// GNU库依赖符号信息
	gnuVersionSymSection := p.F.GetSectionByType(SHT_GNU_VERSYM)
	if gnuVersionSymSection == nil {
		return errors.New("no gnu versym section in file")
	}
	gnuVersionSymSectionData, _ := gnuVersionSymSection.Data()
	p.F.GNUVersion = gnuVer
	p.F.GNUVersionSym = gnuVersionSymSectionData
	return nil

}

// gnuVersion adds Library and Version information to namedSymbol,
// which came from offset i of the symbol table.
func (p *Parser) gnuVersion(i int) (string, string) {
	// Each entry is two bytes.
	i = (i + 1) * 2
	if i >= len(p.F.GNUVersionSym) {
		return "", ""
	}
	j := int(p.F.ByteOrder().Uint16(p.F.GNUVersionSym[i:]))
	if j < 2 || j >= len(p.F.GNUVersion) {
		return "", ""
	}
	n := &p.F.GNUVersion[j]
	return n.File, n.Name
}
