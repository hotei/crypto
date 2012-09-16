package threefish

import (
	"fmt"
	"testing"
)

func TestSkein(t *testing.T) {
	tests := []struct{
		data string
		hash string
	}{
		{"", "BC5B4C50925519C290CC634277AE3D6257212395CBA733BBAD37A4AF0FA06AF41FCA7903D06564FEA7A2D3730DBDB80C1F85562DFCC070334EA4D1D9E72CBA7A"},
		{"\xCC", "26D8382EBDC39072293DDCDDA6568B4ADD2449A05424A12DFBF11595228E9FBF7C542F25EC0F7348B19AD23EF5E97D45E5CFF7BB9969BE332923F33BE53A6D09"},
		{"\xD8\xFA\xBA\x1F\x51\x94\xC4\xDB\x5F\x17\x6F\xAB\xFF\xF8\x56\x92\x4E\xF6\x27\xA3\x7C\xD0\x8C\xF5\x56\x08\xBB\xA8\xF1\xE3\x24\xD7\xC7\xF1\x57\x29\x8E\xAB\xC4\xDC\xE7\xD8\x9C\xE5\x16\x24\x99\xF9", "DE5D2A161B5FE2E087476CBF15F8DF9C35E4BE11E9A9EC01EDC3818B88C4998EB0B4D405E7F4C924DDB3B077410CA73D2E7CD3ED6D87AD126190E445CB97D323"},
		{"\x36\xF9\xF0\xA6\x5F\x2C\xA4\x98\xD7\x39\xB9\x44\xD6\xEF\xF3\xDA\x5E\xBB\xA5\x7E\x7D\x9C\x41\x59\x8A\x2B\x0E\x43\x80\xF3\xCF\x4B\x47\x9E\xC2\x34\x8D\x01\x5F\xFE\x62\x56\x27\x35\x11\x15\x4A\xFC\xF3\xB4\xB4\xBF\x09\xD6\xC4\x74\x4F\xDD\x0F\x62\xD7\x50\x79\xD4\x40\x70\x6B\x05", "436067709B778CD3B60934649C8942D1930D74C36F8308686FB18B39E01DECFCC34EDB363D7EF2FD51353D571BE1019F119EE79A5DA61898927E6DB5BE909D69"},
	}

	for idx, test := range tests {
		h := NewSkein(512, 512)
		fmt.Fprint(h, test.data)
		if got, want := fmt.Sprintf("%X", h.Sum(nil)), test.hash; got != want {
			t.Errorf("%d. hash(%X):", idx, test.data)
			t.Errorf("%d.    got %q", idx, got)
			t.Errorf("%d.   want %q", idx, want)
		}
	}
}

func BenchmarkSkein512(b *testing.B) {
	sk := NewSkein(512, 512)
	data := []byte("\x36\xF9\xF0\xA6\x5F\x2C\xA4\x98\xD7\x39\xB9\x44\xD6\xEF\xF3\xDA\x5E\xBB\xA5\x7E\x7D\x9C\x41\x59\x8A\x2B\x0E\x43\x80\xF3\xCF\x4B\x47\x9E\xC2\x34\x8D\x01\x5F\xFE\x62\x56\x27\x35\x11\x15\x4A\xFC\xF3\xB4\xB4\xBF\x09\xD6\xC4\x74\x4F\xDD\x0F\x62\xD7\x50\x79\xD4\x40\x70\x6B\x05")
	out := make([]byte, 0, sk.Size())

	b.SetBytes(int64(len(data)))
	collect(func(){
		for i := 0; i < b.N; i++ {
			sk.Write(data)
			sk.Sum(out)

			sk.Reset()
			out = out[:0]
		}
	})
}
