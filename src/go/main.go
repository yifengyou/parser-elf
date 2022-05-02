package main

import (
	"fmt"
	"os"
	"parser-elf/elf"
)

func main() {
	// 实现ELF解析，类似readelf -a读取的结果
	p, err := elf.New("gcc-amd64-linux-exec")
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	// 关键函数，Parse解析，fs binstream.Stream 内容解析填充到结构化 F  *File 中
	err = p.Parse()
	if err != nil {
		panic(err)
	}

	// hexdump打印所有节内容（节数据区域、非节头、非程序头）
	for index, sn := range p.F.Sections64 {
		fmt.Println()
		fmt.Printf("[ %d ] Name:[%s] Size:[%d] Offset:[0x%x]\n",
			index,
			sn.SectionName,
			sn.Size, sn.Off,
		)
		fmt.Printf("%s", sn.HexDumpData())
	}

	//os.Exit(0)
	// ELF Header
	p.DumpHeaderIndent()
	p.DumpHeaderWithoutIndent()
	p.DumpSectionHeaders()
	p.DumpProgramHeaders()
	// 各类section挨个安排
	p.DumpDynamicSection()
	p.DumpSymbolTable()
	// 打印可重定位信息
	p.DumpRelaDynSection()
	p.DumpRelaPltSection()
	// 打印 全局偏移表(Global Offset Table)
	p.DumpGotSection()
	p.DumpGotPltSection()



	os.Exit(0)
	jsonFile, err := p.DumpJSON()
	if err != nil {
		panic(err)
	}
	fmt.Println(jsonFile)
}
