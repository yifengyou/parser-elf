package main

import (
	"os"
	"parser-elf/elf"
)

func main() {
	// 实现ELF解析，类似readelf -a读取的结果
	p, err := elf.New("ls")
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	// 关键函数，Parse解析，fs binstream.Stream 内容解析填充到结构化 F  *File 中
	err = p.Parse()
	if err != nil {
		panic(err)
	}

	// ELF Header
	p.DumpHeaderIndent()
	p.DumpHeaderWithoutIndent()
	p.DumpSectionHeaders()
	p.DumpProgramHeaders()
	// 各类section挨个安排
	p.DumpDynamicSection()
	p.DumpSymbolTable()
	//p.DumpRelocationsSection()

	//fmt.Println(p.F.GNUVersionSym)

	os.Exit(0)
	//jsonFile, err := p.DumpJSON()
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println(jsonFile)
}
