#!/usr/bin/python3
import argparse
import os
import subprocess
import sys
from elftools.elf.elffile import ELFFile

CURRENT_VERSION = "0.0.1"


def check_python_version():
    current_python = sys.version_info[0]
    if current_python == 3:
        return
    else:
        raise Exception('Invalid python version requested: %d' % current_python)


def hexdump(data, width=16):
    """
    打印数据的十六进制和 ASCII 表示，类似于 hexdump -C 命令。

    参数:
    data -- 要打印的数据（字节串或字符串）
    width -- 每行显示的字节数，默认为 16
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    num_lines = (len(data) + width - 1) // width

    for i in range(num_lines):
        start = i * width
        end = min((i + 1) * width, len(data))

        hex_part = ' '.join('{:02x}'.format(byte) for byte in data[start:end])
        print(f"{start:08x}: {hex_part:<{width * 3}}", end='')

        ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data[start:end])
        print(f"{'':{width}} {ascii_part}")


def parse_elf_header(elf):
    """
    binutils-2.35.2/elfcpp/elfcpp_internal.h
    template<int size>
    struct Ehdr_data
    {
      unsigned char e_ident[EI_NIDENT];
      Elf_Half e_type;
      Elf_Half e_machine;
      Elf_Word e_version;
      typename Elf_types<size>::Elf_Addr e_entry;
      typename Elf_types<size>::Elf_Off e_phoff;
      typename Elf_types<size>::Elf_Off e_shoff;
      Elf_Word e_flags;
      Elf_Half e_ehsize;
      Elf_Half e_phentsize;
      Elf_Half e_phnum;
      Elf_Half e_shentsize;
      Elf_Half e_shnum;
      Elf_Half e_shstrndx;
    };

    :param elf:
    :return:
    """
    print(f"ELF Header:")
    # ELF 头部信息
    e_ident = elf.header.e_ident
    # 打印ei_开始的信息
    for i in e_ident.items():
        if i[0].startswith('EI_'):
            print(f"{i[0].lower()}: {i[1]}")
    # 打印e_开头的信息
    print(f"e_type:{elf.header['e_type']} # Type")
    print(f"e_machine:{elf.header['e_machine']} # Machine architecture")
    print(f"e_version:{elf.header['e_version']} # Version")
    print(f"e_entry:{hex(elf.header['e_entry'])} # Entry point address")
    print(f"e_phoff:{elf.header['e_phoff']}({hex(elf.header['e_phoff'])})(bytes into file) # Start of program headers")
    print(f"e_shoff:{elf.header['e_shoff']}({hex(elf.header['e_shoff'])})(bytes into file) # Start of section headers")
    print(f"e_flags:{elf.header['e_flags']} # Flags")
    print(f"e_ehsize:{elf.header['e_ehsize']} (bytes) # Size of this header")
    print(f"e_phentsize:{elf.header['e_phentsize']} (bytes) # Size of program headers")
    print(f"e_phnum:{elf.header['e_phnum']} # Number of program headers")
    print(f"e_shentsize:{elf.header['e_shentsize']} (bytes) # Size of section headers")
    print(f"e_shnum:{elf.header['e_shnum']} # Number of section headers")
    print(f"e_shstrndx:{elf.header['e_shstrndx']} # Section header string table index")
    print('-' * 128)


def parse_program_header_table(elf):
    """
    binutils-2.35.2/elfcpp/elfcpp_internal.h

    template<>
    struct Phdr_data<32>
    {
      Elf_Word p_type;
      Elf_types<32>::Elf_Off p_offset;
      Elf_types<32>::Elf_Addr p_vaddr;
      Elf_types<32>::Elf_Addr p_paddr;
      Elf_Word p_filesz;
      Elf_Word p_memsz;
      Elf_Word p_flags;
      Elf_Word p_align;
    };

    template<>
    struct Phdr_data<64>
    {
      Elf_Word p_type;
      Elf_Word p_flags;
      Elf_types<64>::Elf_Off p_offset;
      Elf_types<64>::Elf_Addr p_vaddr;
      Elf_types<64>::Elf_Addr p_paddr;
      Elf_Xword p_filesz;
      Elf_Xword p_memsz;
      Elf_Xword p_align;
    };

    :param elf:
    :return:
    """
    print(f"ELF Program header table:")
    # if not elf.has_program_headers:
    #     print("ELF file does not contain a program header table.")
    #     return

    for segment in elf.iter_segments():
        print(f"p_type:{segment['p_type']:<9} "
              f"p_offset:{segment['p_offset']:<9} "
              f"p_vaddr:0X{segment['p_vaddr']:016X} "
              f"p_paddr:0X{segment['p_paddr']:016X} "
              f"p_filesz:{segment['p_filesz']:<9} "
              f"p_memsz:{segment['p_memsz']:<9} "
              f"p_flags:{segment['p_flags']:<3} "
              f"p_align:0X{segment['p_align']:016X}")

    print('-' * 128)


def parse_typeof_symtab(section):
    """
    binutils-2.35.2/elfcpp/elfcpp_internal.h
    template<int size>
    struct Sym_data;

    template<>
    struct Sym_data<32>
    {
      Elf_Word st_name;
      Elf_types<32>::Elf_Addr st_value;
      Elf_Word st_size;
      unsigned char st_info;
      unsigned char st_other;
      Elf_Half st_shndx;
    };

    template<>
    struct Sym_data<64>
    {
      Elf_Word st_name;
      unsigned char st_info;
      unsigned char st_other;
      Elf_Half st_shndx;
      Elf_types<64>::Elf_Addr st_value;
      Elf_Xword st_size;
    };
    """
    section_offset = section['sh_offset']
    section_size = section['sh_size']
    print(f"section offset:{section_offset}[{hex(section_offset)}] size:{section_size}[{hex(section_size)}] "
          f"entry number {sum(1 for _ in section.iter_symbols())}")
    for symbol in section.iter_symbols():
        sym_type = symbol.entry['st_info']['type']
        print(f"symbol from section {section.name} {section['sh_type']} - symbol name:{symbol.name} "
              f"st_name:{symbol['st_name']} "
              f"st_value: 0x{symbol['st_value']:x} "
              f"st_size:{symbol['st_size']} "
              f"st_other:{symbol['st_other']['visibility']} "
              f"bind:{symbol.entry['st_info']['bind']} "
              f"sym_type:{sym_type}")


def parse_typeof_strtab(section):
    strtab = section.data()
    section_offset = section['sh_offset']
    section_size = section['sh_size']
    print(f"Hexdump String Table Contents {section.name} {section['sh_type']}:")
    print(f"section offset:{section_offset}[{hex(section_offset)}] size:{section_size}[{hex(section_size)}]")
    hexdump(strtab)
    print(f"String Table Contents {section.name} {section['sh_type']}:")
    str_list = strtab.split(b'\x00')
    print(f"section offset:{section_offset}[{hex(section_offset)}] size:{section_size}[{hex(section_size)}] "
          f"entry number {len(str_list)}")
    for s in str_list:
        if s:
            print(f"str from section {section.name} {section['sh_type']} : '{s.decode('utf-8')}'")


def parse_typeof_rela(section):
    """
    template<int size>
    struct Rela_data
    {
      typename Elf_types<size>::Elf_Addr r_offset;
      typename Elf_types<size>::Elf_WXword r_info;
      typename Elf_types<size>::Elf_Swxword r_addend;
    };
    """
    section_offset = section['sh_offset']
    section_size = section['sh_size']
    print(f"section offset:{section_offset}[{hex(section_offset)}] size:{section_size}[{hex(section_size)}] "
          f"entry number {sum(1 for _ in section.iter_relocations())}")
    for rela in section.iter_relocations():
        print(f"r_offset: {hex(rela['r_offset'])} "
              f"r_info: {hex(rela['r_info'])} "
              f"r_addend: {hex(rela['r_addend'])} "
              f"r_info_sym: {hex(rela.entry['r_info_sym'])} "
              f"r_info_type: {hex(rela.entry['r_info_type'])} ")
        # 获取符号名称（如果存在）
        # if rela.entry['r_info_sym'] is not None:
        #     symbol = section.get_symbol(rela.entry['r_info_sym'])
        #     print(f"  Symbol Name: {symbol.name}")
        # else:
        #     print("  Symbol Name: (none)")


def parse_typeof_default(section):
    # just hexdump section
    strtab = section.data()
    section_offset = section['sh_offset']
    section_size = section['sh_size']
    print(f"Hexdump String Table Contents {section.name} {section['sh_type']}:")
    print(f"section offset:{section_offset}[{hex(section_offset)}] size:{section_size}[{hex(section_size)}]")
    hexdump(strtab)
    print(f"String Table Contents {section.name} {section['sh_type']}:")
    str_list = strtab.split(b'\x00')
    print(f"section offset:{section_offset}[{hex(section_offset)}] size:{section_size}[{hex(section_size)}] "
          f"entry number {len(str_list)}")
    for s in str_list:
        s = s.strip().decode('utf-8', errors='ignore')
        if s and s.isprintable():
            print(f"str from section {section.name} {section['sh_type']} : "
                  f"'{s}'")


def parse_all_sections(elf):
    print(f"ELF all section:")
    for section in elf.iter_sections():
        print(f"-> parse name:{section.name} "
              f"sh_name:{section['sh_name']} "
              f"sh_type:{section['sh_type']}")

        if section['sh_type'] == 'SHT_SYMTAB':
            parse_typeof_symtab(section)
        elif section['sh_type'] == 'SHT_STRTAB':
            parse_typeof_strtab(section)
        elif section['sh_type'] == 'SHT_RELA':
            parse_typeof_rela(section)
        else:
            parse_typeof_default(section)

    print('-' * 128)


def parse_section_header_table(elf):
    """
    binutils-2.35.2/elfcpp/elfcpp_internal.h
    // An ELF section header.

    template<int size>
    struct Shdr_data
    {
      Elf_Word sh_name;
      Elf_Word sh_type;
      typename Elf_types<size>::Elf_WXword sh_flags;
      typename Elf_types<size>::Elf_Addr sh_addr;
      typename Elf_types<size>::Elf_Off sh_offset;
      typename Elf_types<size>::Elf_WXword sh_size;
      Elf_Word sh_link;
      Elf_Word sh_info;
      typename Elf_types<size>::Elf_WXword sh_addralign;
      typename Elf_types<size>::Elf_WXword sh_entsize;
    };

    :param elf:
    :return:
    """
    print(f"ELF section header table:")
    # 遍历section header table
    for section in elf.iter_sections():
        print(f"sh_name:{'%s(%s)' % (section.name, section['sh_name']):33}"
              f"sh_size:{'%d(%.3fMB)' % (section['sh_size'], section['sh_size'] / 1024 / 1024):23}"
              f"sh_type:{section['sh_type']:13} "
              f"sh_flags:{section['sh_flags']:<3} "
              f"sh_addr:0X{section['sh_addr']:016X} "
              f"sh_offset:0X{section['sh_offset']:016X} "
              f"sh_link:{section['sh_link']:<3} "
              f"sh_info:{section['sh_info']:<6} "
              f"sh_addralign:{section['sh_addralign']:<5} "
              f"sh_entsize:{section['sh_entsize']}")
    print('-' * 128)


def parse_elf(file_path):
    try:
        # 打开 ELF 文件
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)

            # ELF Header
            parse_elf_header(elf)

            # ELF Program Header Table
            parse_program_header_table(elf)

            # ELF Sections
            # parse_all_sections(elf)

            # ELF Section Header Table
            parse_section_header_table(elf)

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def parse_all_sections_info(elf):
    print(f"ELF all section:")
    for section in elf.iter_sections():
        print(f"-> parse name:{section.name:<25} "
              f"sh_name:{section['sh_name']:<6} "
              f"sh_type:{section['sh_type']}")
    print('-' * 128)


def do_handle_info(args):
    try:
        # 打开 ELF 文件
        with open(args.elf_file, 'rb') as f:
            elf = ELFFile(f)

            # ELF Header
            parse_elf_header(elf)

            # ELF Program Header Table
            parse_program_header_table(elf)

            # ELF Sections
            parse_all_sections_info(elf)

            # ELF Section Header Table
            parse_section_header_table(elf)
    except Exception as e:
        print(f"An error occurred: {e}")


def handle_info(args):
    elf_file_path = os.path.realpath(args.elf_file)
    print(f"Target elf file: {elf_file_path}")
    if not os.path.exists(elf_file_path):
        print("Target elf file does not found!")
        os.exit(1)
    args.elf_file = elf_file_path
    do_handle_info(args)


def do_handle_symbol(args):
    try:
        with open(args.elf_file, 'rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section['sh_type'] == 'SHT_SYMTAB':
                    print(f"-> parse name:{section.name:<25} "
                          f"sh_name:{section['sh_name']:<6} "
                          f"sh_type:{section['sh_type']}")
                    parse_typeof_symtab(section)
    except Exception as e:
        print(f"An error occurred: {e}")
    print('-' * 128)


def handle_symbol(args):
    elf_file_path = os.path.realpath(args.elf_file)
    print(f"Target elf file: {elf_file_path}")
    if not os.path.exists(elf_file_path):
        print("Target elf file does not found!")
        os.exit(1)
    args.elf_file = elf_file_path
    do_handle_symbol(args)


def do_handle_strtable(args):
    try:
        with open(args.elf_file, 'rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section['sh_type'] == 'SHT_STRTAB':
                    print(f"-> parse name:{section.name:<25} "
                          f"sh_name:{section['sh_name']:<6} "
                          f"sh_type:{section['sh_type']}")
                    parse_typeof_strtab(section)
    except Exception as e:
        print(f"An error occurred: {e}")
    print('-' * 128)


def handle_strtable(args):
    elf_file_path = os.path.realpath(args.elf_file)
    print(f"Target elf file: {elf_file_path}")
    if not os.path.exists(elf_file_path):
        print("Target elf file does not found!")
        os.exit(1)
    args.elf_file = elf_file_path
    do_handle_strtable(args)


def handle_vmlinux(args):
    elf_file_path = os.path.realpath(args.elf_file)
    print(f"Target elf file: {elf_file_path}")
    if not os.path.exists(elf_file_path):
        print("Target elf file does not found!")
        os.exit(1)
    args.elf_file = elf_file_path
    print("todo do_handle_vmlinux")


def handle_builtin(args):
    """
    thin archive:
    The version of ar in GNU binutils and Elfutils have an additional "thin archive" format with the magic number
    !<thin>. A thin archive only contains a symbol table and references to the file. The file format is essentially a
    System V format archive where every file is stored without the data sections. Every filename is stored as a
    "long" filename and they are to be resolved as if they were symbolic links.[17]
    :param args:
    :return:
    """
    elf_file_path = os.path.realpath(args.elf_file)
    print(f"Target elf file: {elf_file_path}")
    if not os.path.exists(elf_file_path):
        print("Target elf file does not found!")
        os.exit(1)
    args.elf_file = elf_file_path

    # 使用 ar 命令列出归档中的成员
    result = subprocess.run(['ar', '-tOv', elf_file_path], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error listing archive members: {result.stderr}")
        return

    # 打印归档成员列表
    print(f"Members of thin archive '{elf_file_path}':")
    member_list = result.stdout.splitlines()
    for member in member_list:
        print(member)
    print(f"Total number: {len(member_list)}")


def main():
    global CURRENT_VERSION
    check_python_version()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-v", "--version", action="store_true",
                        help="show program's version number and exit")
    parser.add_argument("-h", "--help", action="store_true",
                        help="show this help message and exit")

    subparsers = parser.add_subparsers()

    # 定义base命令用于集成
    parent_parser = argparse.ArgumentParser(add_help=False, description="sysup - a tool for kernel development")
    parent_parser.add_argument("elf_file", help="Path to the ELF file to process.")
    parent_parser.add_argument("-V", "--verbose", default=None, action="store_true", help="show verbose output")
    parent_parser.add_argument('--debug', default=None, action="store_true", help="enable debug output")

    # 添加子命令 info
    parser_info = subparsers.add_parser('info', parents=[parent_parser], help="info elf file")
    parser_info.set_defaults(func=handle_info)

    # 添加子命令 symbol
    parser_symbol = subparsers.add_parser('symbol', parents=[parent_parser], help="symbol elf file")
    parser_symbol.set_defaults(func=handle_symbol)

    # 添加子命令 strtable
    parser_strtable = subparsers.add_parser('strtable', parents=[parent_parser], help="strtable elf file")
    parser_strtable.set_defaults(func=handle_strtable)

    # 添加子命令 vmlinux
    parser_vmlinux = subparsers.add_parser('vmlinux', parents=[parent_parser], help="linux kernel vmlinux parser")
    parser_vmlinux.set_defaults(func=handle_vmlinux)

    # 添加子命令 buitin
    parser_builtin = subparsers.add_parser('builtin', parents=[parent_parser],
                                           help="linux kernel built-in parser(thin archive)")
    parser_builtin.set_defaults(func=handle_builtin)

    # 开始解析命令
    args = parser.parse_args()

    if args.version:
        print("parser-elf %s" % CURRENT_VERSION)
        sys.exit(0)
    elif args.help or len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
