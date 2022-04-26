package elf

import (
	"compress/zlib"
	"io"
	"math"
)

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
func (s *ELF32Section) Data() ([]byte, error) {

	var rs io.ReadSeeker
	data := make([]byte, s.Size)

	if s.Flags&uint32(SHF_COMPRESSED) == 0 {
		rs = io.NewSectionReader(s.sr, 0, 1<<63-1)
	} else if s.compressionType == COMPRESS_ZLIB {
		rs = &readSeekerFromReader{
			reset: func() (io.Reader, error) {
				fr := io.NewSectionReader(s.sr, s.compressionOffset, int64(s.Size)-s.compressionOffset)
				return zlib.NewReader(fr)
			},
			size: int64(s.Size),
		}
	}
	n, err := io.ReadFull(rs, data)
	return data[0:n], err
}

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
// 获取当前节数据，返回字节数组
func (s *ELF64Section) Data() ([]byte, error) {

	var rs io.ReadSeeker
	data := make([]byte, s.Size)

	if s.Flags&uint64(SHF_COMPRESSED) == 0 {
		// s.sr 已经是读取的节的数据，如果么有压缩，直接完整读取即可
		// 小骚的最大数 MaxInt64  = 1<<63 - 1
		// io.NewSectionReader 遇到EOF会停下来
		rs = io.NewSectionReader(s.sr, 0, math.MaxInt64)
		// 其实s.sr已经是io.NewSectionReader读取的结果
		// 但io.NewSectionReader可以嵌套多次，只需要实现了Read接口即可
	} else if s.compressionType == COMPRESS_ZLIB {
		// 如果节做了压缩，则需要解压
		rs = &readSeekerFromReader{
			reset: func() (io.Reader, error) {
				fr := io.NewSectionReader(s.sr, s.compressionOffset, int64(s.Size)-s.compressionOffset)
				return zlib.NewReader(fr)
			},
			size: int64(s.Size),
		}
	}
	// func ReadFull(r Reader, buf []byte) (n int, err error)
	// 读取字节切片，放到data中
	n, err := io.ReadFull(rs, data)
	return data[0:n], err
}
