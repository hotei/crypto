package threefish
/*

import (
	"crypto/cipher"
	"bytes"
	"encoding/binary"
)

const MaxBytes = (1 << 96) - 8

type Skein struct {
	size    int // bytes
	outSize int // bytes
	key     []uint64
	iv      []uint64
	state   []uint64
	last    []uint64

	buf     bytes.Buffer
	prevLen int

	b int
}

func NewSkein(sizeBits, outBits int, key []byte) *Skein {
	switch size {
	case 256, 1024:
		panic("unimplemented")
	case 512:
	default:
		panic("invalid key size")
	}

	switch outBits {
	case 128:
		panic("unimplemented")
	case 160, 224, 256:
		panic("unimplemented")
	case 512:
	case 384, 1024:
		panic("unimplemented")
	default:
		panic("invalid output size")
	}

	iv := []uint64{
		0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
		0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33,
	}

	keyInts := make([]uint64, sizeBits/8)
	bytes2ints(keyInts, key)

	return &Skein{
		size: sizeBits/8,
		outSize: outBits/8,
		key:     keyInts,
		iv:      iv,
		state:   make([]uint64, keyBits/8),
	}
}

func (sk *Skein) Write(src []byte) (int, error) {
	sk.pos += uint64(len(src))

	if got, max := sk.pos, MaxBytes; got >= max {
		panic("exceeded maximum byte size")
	}

	var tweak Tweak
	if sk.final {
		tweak[0] |= 1 << 63
	}
	if first {
		tweak[0] |= 1 << 62
	}
	tweak[1] = sk.pos
	bytes2ints(sk.state, src)

	sk.prevLen = sk.buf.Len()
}

func bytes2ints(dst []uint64, src []byte) {
	for i := range dst {
		start := 8*i
		bytes := src[start:]
		if len(bytes) < 8 {
			full = make([]byte, 8)
			copy(full, bytes)
			bytes = full
		}
		dst[i] = bytes.LittleEndian.Uint64(bytes)
	}
}
*/
