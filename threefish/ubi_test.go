package threefish

import (
	"fmt"
	"testing"
	"strings"
)

func TestSkein(t *testing.T) {
	tests := []struct {
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

func TestSkeinInternal(t *testing.T) {
	if !debugSkein {
		fmt.Println("WARNING: Skipping internal skein tests (debugSkein = false)")
		return
	}
	if debugThreefish {
		fmt.Println("WARNING: Skipping internal skein tests (debugThreefish = true)")
		return
	}

	tests := []struct {
		data []byte
		want string
	}{{
		data: []byte{
			0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
			0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
			0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8, 0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0,
			0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8, 0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0,
			0xBF, 0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1, 0xB0,
			0xAF, 0xAE, 0xAD, 0xAC, 0xAB, 0xAA, 0xA9, 0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0,
			0x9F, 0x9E, 0x9D, 0x9C, 0x9B, 0x9A, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
			0x8F, 0x8E, 0x8D, 0x8C, 0x8B, 0x8A, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80,
		},
		want: `
:Skein-512:  Block: outBits= 512. T0=000040. Type=MSG.  Flags= First
  Tweak:
     00000000.00000040  70000000.00000000 
  State words:
     4903ADFF.749C51CE  0D95DE39.9746DF03  8FD19341.27C79BCE  9A255629.FF352CB1 
     5DB62599.DF6CA7B0  EABE394C.A9D5C3F4  991112C7.1A75B523  AE18A40B.660FCC33 
  Input block (bytes):
     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0
     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0
     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0
     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0

:Skein-512:  [state after plaintext feedforward]=
     C3731547.5758343F  35F9BF51.4B734529  09DB8493.7DDEFB6B  E8D98CD4.482240CE 
     6B981140.54E9EDF1  91FE1BD1.D8558B18  C3EA44D8.D6E089C9  460CF7C5.84AD44C2 
    ----------

:Skein-512:  Block: outBits= 512. T0=000080. Type=MSG.  Flags= Final
  Tweak:
     00000000.00000080  B0000000.00000000 
  State words:
     C3731547.5758343F  35F9BF51.4B734529  09DB8493.7DDEFB6B  E8D98CD4.482240CE 
     6B981140.54E9EDF1  91FE1BD1.D8558B18  C3EA44D8.D6E089C9  460CF7C5.84AD44C2 
  Input block (bytes):
     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0
     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0
     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90
     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80

:Skein-512:  [state after plaintext feedforward]=
     42BA6697.72C1BCFE  423AEC4D.934365F1  A2D9061A.4E4CE337  5BA3E9B6.56BA3214 
     90CCE7E3.F4436541  8C6F15B2.7DA4FA14  23A818E0.88F7013B  E0017468.86D857C6 
    ----------

:Skein-512:  Block: outBits= 512. T0=000008. Type=OUT.  Flags= First Final
  Tweak:
     00000000.00000008  FF000000.00000000 
  State words:
     42BA6697.72C1BCFE  423AEC4D.934365F1  A2D9061A.4E4CE337  5BA3E9B6.56BA3214 
     90CCE7E3.F4436541  8C6F15B2.7DA4FA14  23A818E0.88F7013B  E0017468.86D857C6 
  Input block (bytes):
     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00

:Skein-512:  [state after plaintext feedforward]=
     DDC463C2.10A5CC91  09330733.0A5310D0  1B7E7408.F3318662  2EB9CA51.E490AACB 
     738718F4.7A088851  A2A76766.3E3032A3  00003921.746F8510  B7ADA5A2.8B8EF471 
    ----------

:Skein-512:  Final output=
     91 CC A5 10  C2 63 C4 DD  D0 10 53 0A  33 07 33 09
     62 86 31 F3  08 74 7E 1B  CB AA 90 E4  51 CA B9 2E
     51 88 08 7A  F4 18 87 73  A3 32 30 3E  66 67 A7 A2
     10 85 6F 74  21 39 00 00  71 F4 8E 8B  A2 A5 AD B7
`,
	}}

	for idx, test := range tests {
		got := collect(func(){
			sk := NewSkein(512, 512)
			sk.Write(test.data)
			sk.Sum(nil)
		})

		if got, want := strings.TrimSpace(got.String()), strings.TrimSpace(test.want); got != want {
			t.Errorf("%d. got|eq|want:\n%s", idx, sideBySide(got, want))
		}
	}
}

func BenchmarkSkein512(b *testing.B) {
	sk := NewSkein(512, 512)
	data := []byte("\x36\xF9\xF0\xA6\x5F\x2C\xA4\x98\xD7\x39\xB9\x44\xD6\xEF\xF3\xDA\x5E\xBB\xA5\x7E\x7D\x9C\x41\x59\x8A\x2B\x0E\x43\x80\xF3\xCF\x4B\x47\x9E\xC2\x34\x8D\x01\x5F\xFE\x62\x56\x27\x35\x11\x15\x4A\xFC\xF3\xB4\xB4\xBF\x09\xD6\xC4\x74\x4F\xDD\x0F\x62\xD7\x50\x79\xD4\x40\x70\x6B\x05")
	out := make([]byte, 0, sk.Size())

	b.SetBytes(int64(len(data)))
	collect(func() {
		for i := 0; i < b.N; i++ {
			sk.Write(data)
			sk.Sum(out)

			sk.Reset()
			out = out[:0]
		}
	})
}
