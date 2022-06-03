package cipher

import (
	"bytes"
	"fmt"
	"testing"
)

var aesTestCases = []struct {
	name    string
	key     []byte
	iv      []byte
	data    []byte
	mode    AesBlockMode
	padding AesPaddingScheme
	output  []byte
}{
	// Tests from NIST SP 800-38A pp 27-29
	// https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/crypto/cipher/cbc_aes_test.go
	{
		name:    "AES-128-CFB",
		key:     []byte{160, 153, 156, 74, 55, 224, 78, 74, 56, 176, 207, 163, 173, 44, 109, 211},
		iv:      []byte{51, 49, 52, 50, 49, 52, 52, 49, 52, 56, 55, 50, 53, 49, 48, 57},
		data:    []byte("Sample message for keylen<blocklen"),
		mode:    CBC,
		padding: PKCS7,
		output: []byte{
			113, 137, 144, 149, 72, 185, 22, 143, 22, 216, 5, 84, 140, 145,
			204, 97, 177, 231, 216, 49, 14, 193, 55, 253, 200, 60, 40, 165,
			238, 62, 170, 190, 51, 8, 206, 43, 182, 59, 4, 130, 62, 78,
			231, 229, 118, 180, 59, 104,
		},
	},
}

func TestAesEncrypt(t *testing.T) {
	for _, test := range aesTestCases {
		t.Run(fmt.Sprintf("Test: %s", test.name), func(t *testing.T) {
			aes := Aes{
				key:     test.key,
				iv:      test.iv,
				mode:    test.mode,
				padding: test.padding}
			cipherText, err := aes.Encrypt(test.data)
			if err != nil {
				t.Errorf("Encrypt() error = %v", err)
				return
			}
			if !bytes.Equal(cipherText, test.output) {
				t.Errorf("Encrypt() = %v, want %v", cipherText, test.output)
			}
		})
	}
}

// Test aes encryption
func TestAesCipher(t *testing.T) {
	key := []byte{160, 153, 156, 74, 55, 224, 78, 74, 56, 176, 207, 163, 173, 44, 109, 211}
	iv := []byte{51, 49, 52, 50, 49, 52, 52, 49, 52, 56, 55, 50, 53, 49, 48, 57}
	plaintext := []byte("{\"requestId\":\"23\",\"actionName\":\"SELLER_SETTLEMENT_STATUS\",\"partnerKey\":\"cmYydUcwVU\",\"p1\":\"PRN2001202204\"}")
	aes := Aes{
		key:     key,
		iv:      iv,
		mode:    CBC,
		padding: PKCS7}
	ciphertext, err := aes.Encrypt(plaintext)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	result, err := aes.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("got %q, wanted %q", string(result), string(plaintext))
	}
}

func TestAesEncryptBase64(t *testing.T) {
	key := []byte{160, 153, 156, 74, 55, 224, 78, 74, 56, 176, 207, 163, 173, 44, 109, 211}
	iv := []byte{51, 49, 52, 50, 49, 52, 52, 49, 52, 56, 55, 50, 53, 49, 48, 57}
	output := "1sNzHc+KAq7EyRM/yXw4NA=="
	plaintext := "{\"name\":\"test\"}"
	aes := Aes{
		key:     key,
		iv:      iv,
		mode:    CBC,
		padding: PKCS7}
	ciphertext, err := aes.EncryptBase64(plaintext)
	if err != nil {
		panic(err)
	}

	if output != ciphertext {
		t.Errorf("got %q, wanted %q", ciphertext, output)
	}
}
