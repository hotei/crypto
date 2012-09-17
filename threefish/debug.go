package threefish

import (
	"fmt"
	"io"
	"os"
	"bytes"
	"strings"
	"text/tabwriter"
)

var debugWriter io.Writer = os.Stderr

func debugWords(data []uint64) {
	if debugWriter == nil {
		return
	}

	for i := 0; i < len(data); {
		fmt.Fprintf(debugWriter, "    ")
		for j := 0; j < 4 && i < len(data); i, j = i+1, j+1 {
			fmt.Fprintf(debugWriter, " %08X.%08X ", data[i]>>32, uint32(data[i]))
		}
		fmt.Fprintf(debugWriter, "\n")
	}
}

func debugBytes(data []byte) {
	if debugWriter == nil {
		return
	}

	for i := 0; i < len(data); {
		fmt.Fprintf(debugWriter, "    ")
		for j := 0; j < 16 && i < len(data); i, j = i+1, j+1 {
			fmt.Fprintf(debugWriter, " %02X", data[i])
			if j % 4 == 3 {
				fmt.Fprintf(debugWriter, " ")
			}
		}
		fmt.Fprintf(debugWriter, "\n")
	}
}

func debugf(format string, args ...interface{}) {
	if debugWriter == nil {
		return
	}

	fmt.Fprintf(debugWriter, format+"\n", args...)
}

func sprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

func panicf(format string, args ...interface{}) {
	panic(sprintf(format, args...))
}

func collect(f func()) *bytes.Buffer {
	b := new(bytes.Buffer)
	defer func(w io.Writer){ debugWriter = w }(debugWriter)
	debugWriter = b	
	f()
	return b
}

func sideBySide(a, b string) string {
	buf := new(bytes.Buffer)
	out := tabwriter.NewWriter(buf, 0, 0, 8, ' ', 0)

	aLines, bLines := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(aLines) || i < len(bLines); i++ {
		var lhs, rhs string
		if i < len(aLines) {
			lhs = aLines[i]
		}
		if i < len(bLines) {
			rhs = bLines[i]
		}
		eq := strings.TrimSpace(lhs) == strings.TrimSpace(rhs)
		fmt.Fprintf(out, "%s\t%v\t%s\n", lhs, eq, rhs)
	}
	out.Flush()
	return strings.TrimRight(buf.String(), "\n")
}
