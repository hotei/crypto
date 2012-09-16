package threefish

import (
	"encoding/binary"
)

const debugSkein = false

type Skein struct {
	// Store the configured bounds of the skein hash
	size    int // bytes
	outSize int // bytes

	// Store internal state
	pos    uint64
	offset int
	bytes  []byte
	plain  []uint64

	// Normal state
	chain []uint64
	state []uint64
}

func NewSkein(sizeBits, outBits int) *Skein {
	switch sizeBits {
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

	chain := []uint64{ // only for Skein-512-512!
		0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
		0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33,
	}

	return &Skein{
		size:    sizeBits / 8,
		outSize: outBits / 8,
		bytes:   make([]byte, sizeBits/8),
		plain:   make([]uint64, sizeBits/8/8),
		chain:   chain,
		state:   make([]uint64, sizeBits/8/8),
	}
}

// Size returns the number of bytes that will be returned
// from a call to Sum.
func (sk *Skein) Size() int {
	return sk.outSize
}

// BlockSize returns the block size of the underlying
// threefish block cipher for this Skein.
func (sk *Skein) BlockSize() int {
	return sk.size
}

func (sk *Skein) Reset() {
	copy(sk.chain, []uint64{ // only for Skein-512-512!
		0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
		0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33,
	})
	sk.pos, sk.offset = 0, 0
}

func (sk *Skein) apply(opt TweakOption) {
	bytes2ints(sk.plain, sk.bytes[:sk.offset])

	if sk.pos == 0 {
		opt |= FirstBlockOption
	}
	sk.pos += uint64(sk.offset) * 8

	tweak := makeTweak(MessageType, sk.pos, opt)
	copy(sk.state, sk.plain)

	if debugSkein {
		debugf("tweak")
		debugWords(tweak[:])
		debugf("chain input")
		debugWords(sk.chain)
		debugf("state input")
		debugWords(sk.state)
	}

	encrypt512(tweak, sk.chain, sk.state)

	if debugSkein {
		debugf("state output")
		debugWords(sk.state)
	}

	// Plaintext feedforward
	for i := range sk.chain {
		sk.chain[i] = sk.state[i] ^ sk.plain[i]
	}

	if debugSkein {
		debugf("after feedforward")
		debugWords(sk.chain)
	}

	sk.offset = 0
}

func (sk *Skein) output() {
	// Zero out the plaintext (the "counter" for the output xform)
	for i := range sk.state {
		sk.state[i] = 0
	}

	// Compute the "output" tweak
	tweak := makeTweak(OutputType, 0, 0)

	if debugSkein {
		debugf("tweak")
		debugWords(tweak[:])
		debugf("chain input")
		debugWords(sk.chain)
		debugf("state input")
		debugWords(sk.state)
	}

	// UBI(G, ctr, Tout)
	encrypt512(tweak, sk.chain, sk.state)

	if debugSkein {
		debugf("final output")
		debugWords(sk.state)
	}
}

func (sk *Skein) Write(src []byte) (int, error) {
	cnt := len(src)
	for len(src) > 0 {
		// Buffer as many bytes as we can fit
		n := copy(sk.bytes[sk.offset:], src)
		sk.offset += n

		// If there is more data, we need to process a block
		if n < len(src) {
			sk.apply(0)
		}

		// Slice off the data we processed
		src = src[n:]
	}
	return cnt, nil
}

type TweakType uint64

const (
	KeyType             TweakType = 0 << 48
	ConfigType          TweakType = 4 << 48
	PersonalizationType TweakType = 8 << 48
	PublicKeyType       TweakType = 12 << 48
	KDFType             TweakType = 16 << 48
	NonceType           TweakType = 20 << 48
	MessageType         TweakType = 48 << 48
	OutputType          TweakType = 63 << 48
)

type TweakOption uint64

const (
	FirstBlockOption TweakOption = 1 << 62
	FinalBlockOption TweakOption = 1 << 63
	BitPadOption     TweakOption = 1 << 47
)

func makeTweak(ttype TweakType, bitpos uint64, options TweakOption) Tweak {
	return Tweak{uint64(ttype) | uint64(options), bitpos}
}

func (sk *Skein) Sum(b []byte) []byte {
	sk.apply(FinalBlockOption)
	sk.output()
	return appendInts(b, sk.state...)
}

func appendInts(dst []byte, src ...uint64) []byte {
	var b [8]byte
	for _, u := range src {
		binary.LittleEndian.PutUint64(b[:], u)
		dst = append(dst, b[:]...)
	}
	return dst
}

func bytes2ints(dst []uint64, src []byte) {
	for i := range dst {
		start := 8 * i
		if start >= len(src) {
			dst[i] = 0
			continue
		}

		bytes := src[start:]
		if len(bytes) < 8 {
			full := make([]byte, 8)
			copy(full, bytes)
			bytes = full
		}

		dst[i] = binary.LittleEndian.Uint64(bytes)
	}
}
