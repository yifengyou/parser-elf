# elf解析

```
Something I hope you know before go into the coding~
First, please watch or star this repo, I'll be more happy if you follow me.
Bug report, questions and discussion are welcome, you can post an issue or pull a request.
```

## 本仓库内容

1. elf结构
2. go elf解析


## 相关站点

* GitHub地址:<https://github.com/yifengyou/parser-elf>
* GitBook地址:<https://yifengyou.gitbooks.io/parser-elf/content/>


## elf简介

PC平台流行的**可执行文件格式（Executable）**主要包含如下两种，它们都是 **COFF（Common File Format）**格式的变种。

* Windows下的**PE（Portable Executable）**
* Linux下的**ELF（Executable Linkable Format）**

目标文件就是源代码经过编译后但未进行连接的那些中间文件（Windows的.obj和Linux的.o），它与可执行文件的格式非常相似，所以一般跟可执行文件格式一起采用同一种格式存储。**在Windows下采用PE-COFF文件格式；Linux下采用ELF文件格式。**

事实上，除了可执行文件外，**动态链接库（DDL，Dynamic Linking Library）**、**静态链接库（Static Linking Library）** 均采用可执行文件格式存储。它们在Window下均按照PE-COFF格式存储；Linux下均按照ELF格式存储。只是文件名后缀不同而已。

* 动态链接库：Windows的.dll、Linux的.so
* 静态链接库：Windows的.lib、Linux的.a

**ELF(Executable and Linking Format)**，即“**可执行可连接格式**”，最初由 UNIX系统实验室(UNIX System Laboratories – USL)做为应用程序二进制接口(Application Binary Interface - ABI)的一部分而制定和发布。 ELF 作为一种可移植的格式，被TIS 应用于基于 Intel 架构 32 位计算机的各种操作系统上。

ELF 的最大特点在于它有比较广泛的适用性，通用的二进制接口定义使之可以平滑地移植到多种不同的操作环境上。这样，不需要为每一种操作系统都定义一套不同的接口，因此减少了软件的重复编码与编译，加强了软件的可移植性。

ELF 文件格式规范由**TIS(Tool Interface Standards – 工具接口标准)**委员会制定，TIS 委员会是一个微型计算机工业的联合组织，它致力于为 32 位操作系统下的开发工具提供标准化的软件接口。



## 目录

* [elf简介](docs/elf简介/elf简介.md)
* [elf静态结构](docs/elf静态结构/elf静态结构.md)
* [elf装载](docs/elf装载/elf装载.md)
* [elf动态连接](docs/elf动态连接/elf动态连接.md)



## 常见名词对照

| 常见名词         | 全拼                    |
| ---------------- | ----------------------- |
| 可执行可连接格式 | ELF                     |
| ELF 文件头       | ELF header              |
| 基地址           | base address            |
| 动态连接器       | dynamic linker          |
| 动态连接         | dynamic linking         |
| 全局偏移量表     | global offset table     |
| 哈希表           | hash table              |
| 初始化函数       | initialization function |
| 连接编辑器       | link editor             |
| 目标文件         | object file             |
| 函数连接表       | procedure linkage table |
| 程序头           | program header          |
| 程序头表         | program header table    |
| 程序解析器       | program interpreter     |
| 重定位           | relocation              |
| 共享目标         | shared object           |
| 节               | section                 |
| 节头             | section header          |
| 节头表           | section header table    |
| 段               | segment                 |
| 字符串表         | string table            |
| 符号表           | symbol table            |
| 终止函数         | termination function    |



---
