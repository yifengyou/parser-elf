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
	err = p.Parse()
	if err != nil {
		panic(err)
	}

	// ELF Header
	p.DumpHeaderIndent()
	p.DumpHeaderWithoutIndent()
	p.DumpSectionHeaders()

	os.Exit(0)
	//jsonFile, err := p.DumpJSON()
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println(jsonFile)
}
