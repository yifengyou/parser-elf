package main

import (
	"fmt"
	"parser-elf/elf"
)

func main() {

	p, err := elf.New("/bin/ls")
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	err = p.Parse()
	if err != nil {
		panic(err)
	}
	jsonFile, err := p.DumpJSON()
	if err != nil {
		panic(err)
	}
	fmt.Println(jsonFile)
}
