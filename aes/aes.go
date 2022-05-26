package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
)

// generate a 16-byte random key using
func GenEncryptionKey() *[16]byte {
	key := [16]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// generate a 16-byte random key using a given character set
func GenInitizationVector(charset string) *[16]byte {
	iv := [16]byte{}
	for i := range iv {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		iv[i] = charset[num.Int64()]
	}
	return &iv
}

func Encrypt(key, iv, text []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	bPlaintext := PKCS5Padding(text, aes.BlockSize)
	cipherText := make([]byte, len(bPlaintext))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText, bPlaintext)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Decrypt(key, iv, text []byte) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(cipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(cipherText, cipherText)
	cipherText = []byte(strings.TrimSpace(string(cipherText)))
	return string(cipherText), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
