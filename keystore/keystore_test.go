package keystore

import (
	"testing"
)

func TestGenEncryptionKey(t *testing.T) {
	key, err := GenEncryptionKey(32)
	if err != nil {
		t.Errorf("GenEncryptionKey() error = %v", err)
		return
	}
	if len(*key) != 32 {
		t.Errorf("GenEncryptionKey() = %v, want %v", len(*key), 32)
	}
}
