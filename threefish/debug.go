package threefish

import (
	"fmt"
	"io"
	"os"
	"bytes"
)

var debugWriter io.Writer = os.Stderr

func debugWords(data []uint64) {
	if debugWriter == nil {
		return
	}

	var i int
	for i < len(data) {
		fmt.Fprintf(debugWriter, "    ")
		for j := 0; j < 4 && i < len(data); i, j = i+1, j+1 {
			fmt.Fprintf(debugWriter, " %08X.%08X ", data[i]>>32, uint32(data[i]))
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
