package elf

import (
	"fmt"
)

// DumpJSON marshals the entire binary representation into JSON Format.
func (p *Parser) DumpHeaderIndent() {
	fmt.Println("ELF Header:")
	fmt.Printf("Magic:   ")
	for _, value := range p.F.Ident.Magic {
		fmt.Printf("%.2x ", value)
	}
	fmt.Println("")
	fmt.Printf("Class:                             %s\n", ClassToString(p.F.Ident.Class))
	fmt.Printf("Data:                              %s\n", ByteOrderToString(p.F.Ident.Data))
	fmt.Printf("Version:                           %s\n", VersionToString(p.F.Ident.Version))
	fmt.Printf("OS/ABI:                            %s\n", p.F.Ident.OSABI.String())
	fmt.Printf("ABI Version:                       %d\n", p.F.Ident.ABIVersion)
}

func (p *Parser) DumpHeaderWithoutIndent() {
	switch p.F.Ident.Class {
	case ELFCLASS32:
		fmt.Printf("Type:                              %s\n", Type(p.F.Header32.Type).String())
		fmt.Printf("Machine:                           %s\n", Machine(p.F.Header32.Machine).String())
	case ELFCLASS64:
		fmt.Printf("Type:                              %s\n", Type(p.F.Header64.Type).String())
		fmt.Printf("Machine:                           %s\n", Machine(p.F.Header64.Machine).String())
	default:
		fmt.Printf("Type:                              %s\n", "Unkown type")
		fmt.Printf("Machine:                           %s\n", Machine(p.F.Header32.Machine).String())
	}


}
