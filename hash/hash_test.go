package hash

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var hashTestCases = []struct {
	name  string
	in    string
	out   string
	htype HashType
}{
	{
		name:  "SHA256#1",
		in:    "test",
		out:   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		htype: SHA256,
	},
	{
		name:  "SHA1#1",
		in:    "This is a SHA sign test",
		out:   "5260de65bcfeadccc7411b50d97c8a3dca93b8ce",
		htype: SHA1,
	},
	{
		name:  "SHA1#2",
		in:    "This is a PSS sign test",
		out:   "f01ab62e2de6a061806ff8091e51f719aea2327f",
		htype: SHA1,
	},
	{
		name:  "SHA1#3",
		in:    "",
		out:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		htype: SHA1,
	},
}

func TestHash(t *testing.T) {
	for _, test := range hashTestCases {
		t.Run(fmt.Sprintf("TestHash: %s:", test.name), func(t *testing.T) {
			digest, err := Hash(test.htype, []byte(test.in))
			if err != nil {
				t.Errorf("TestHash Hash(%s) failed due to Hash: %s", test.in, err)
			}
			if hex.EncodeToString(digest) != test.out {
				t.Errorf("TestHash Hash(%s) failed, got %s, want %s", test.in, hex.EncodeToString(digest), test.out)
			}
		})
	}
}

var hashBase64TestCases = []struct {
	name  string
	in    string
	out   string
	htype HashType
}{
	{
		name:  "SHA256#1",
		in:    "test",
		out:   "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
		htype: SHA256,
	},
	{
		name:  "SHA1#1",
		in:    "This is a SHA sign test",
		out:   "UmDeZbz+rczHQRtQ2XyKPcqTuM4=",
		htype: SHA1,
	},
	{
		name:  "SHA1#2",
		in:    "This is a PSS sign test",
		out:   "8Bq2Li3moGGAb/gJHlH3Ga6iMn8=",
		htype: SHA1,
	},
}

func TestHashBase64(t *testing.T) {
	for _, test := range hashBase64TestCases {
		t.Run(fmt.Sprintf("TestHash: %s:", test.name), func(t *testing.T) {
			digest, err := HashBase64(test.htype, []byte(test.in))
			if err != nil {
				t.Errorf("TestHash Hash(%s) failed due to Hash: %s", test.in, err)
			}
			if digest != test.out {
				t.Errorf("TestHash Hash(%s) failed, got %s, want %s", test.in, digest, test.out)
			}
		})
	}
}
