package cipher

import (
	"bytes"
	"testing"
)

var paddingTestCases = []struct {
	src       []byte
	dst       []byte
	blockSize int
}{
	{
		src:       []byte{0x1, 0x2, 0x3, 0x10},
		dst:       []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4},
		blockSize: 8,
	},
	{src: []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0},
		dst:       []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8},
		blockSize: 8,
	},
}

func TestPad(t *testing.T) {
	for _, test := range paddingTestCases {
		padded, err := pad(test.src, test.blockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if !bytes.Equal(test.dst, padded) {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.dst, padded)
		}
	}
}
