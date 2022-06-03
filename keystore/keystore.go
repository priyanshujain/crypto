package keystore

import (
	"crypto/rand"
	"io"
	"math/big"
)

// generate a variable sized byte random key using
func GenEncryptionKey(size int) (*[]byte, error) {
	key := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// generate a variable sized byte random key using a given character set
// example charset "0123456789" when only digits are required
func GenEncryptionKeyWithCharset(charset string, size int) (*[]byte, error) {
	iv := make([]byte, size)
	for i := range iv {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return nil, err
		}
		iv[i] = charset[num.Int64()]
	}
	return &iv, nil
}
