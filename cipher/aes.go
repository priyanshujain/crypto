package cipher

// AES encryption
// Input: mode, padding, key, initialization vector, plaintext
// output cipherText

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
)

type Aes struct {
	key     []byte
	iv      []byte
	mode    string
	padding string
}

// error when cipher size is less than block size of AES
var ErrShortBlock = errors.New("cipher text too short")

func (x *Aes) cfbEncrypt(block cipher.Block, src, dst []byte) error {
	stream := cipher.NewCFBEncrypter(block, x.iv)
	stream.XORKeyStream(dst, src)
	return nil
}

func (x *Aes) cfbDecrypt(block cipher.Block, src, dst []byte) error {
	stream := cipher.NewCFBDecrypter(block, x.iv)
	stream.XORKeyStream(dst, src)
	return nil
}

func (x *Aes) cbcEncrypt(block cipher.Block, src, dst []byte) error {
	stream := cipher.NewCBCEncrypter(block, x.iv)
	stream.CryptBlocks(dst, src)
	return nil
}

func (x *Aes) cbcDecrypt(block cipher.Block, src, dst []byte) error {
	stream := cipher.NewCBCDecrypter(block, x.iv)
	stream.CryptBlocks(dst, src)
	return nil
}

func (x *Aes) ctrEncrypt(block cipher.Block, src, dst []byte) error {
	stream := cipher.NewCTR(block, x.iv)
	stream.XORKeyStream(dst, src)
	return nil
}

func (x *Aes) ctrDecrypt(block cipher.Block, src, dst []byte) error {
	stream := cipher.NewCTR(block, x.iv)
	stream.XORKeyStream(dst, src)
	return nil
}

// padding algorithms
// PKCS5, PKCS7, ANSIX923, ISO10126
func applyPadding(src []byte, padding string) (padText []byte, err error) {
	padding = strings.ToUpper(padding)
	switch padding {
	case "PKCS5":
		padText, err = pkcs5Pad(src, aes.BlockSize)
	case "PKCS7":
		padText, err = pkcs7Pad(src, aes.BlockSize)
	default:
		return nil, errors.New("unsupported padding algorithm")
	}
	if err != nil {
		return nil, err
	}
	return padText, nil
}

// remove extra padding from decrypted text
func trimPadding(src []byte, padding string) (padText []byte, err error) {
	padding = strings.ToUpper(padding)
	switch padding {
	case "PKCS5":
		padText, err = pkcs5Unpad(src, aes.BlockSize)
	case "PKCS7":
		padText, err = pkcs7Unpad(src, aes.BlockSize)
	default:
		return nil, errors.New("unsupported padding algorithm")
	}
	if err != nil {
		return nil, err
	}
	return padText, nil
}

func (x *Aes) Encrypt(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(x.key)
	if err != nil {
		return nil, err
	}
	if x.padding != "" {
		src, err = applyPadding(src, x.padding)
		if err != nil {
			return nil, err
		}
	}
	dst := make([]byte, len(src))
	switch x.mode {
	case "CFB":
		x.cfbEncrypt(block, src, dst)
	case "CTR":
		x.ctrEncrypt(block, src, dst)
	case "CBC":
		x.cbcEncrypt(block, src, dst)
	}
	return dst, nil
}

func (x *Aes) Decrypt(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(x.key)
	if err != nil {
		return nil, err
	}
	if len(src) < aes.BlockSize {
		return nil, ErrShortBlock
	}
	dst := make([]byte, len(src))
	switch x.mode {
	case "CFB":
		x.cfbDecrypt(block, src, dst)
	case "CTR":
		x.ctrDecrypt(block, src, dst)
	case "CBC":
		x.cbcDecrypt(block, src, dst)
	}

	if x.padding != "" {
		dst, err = trimPadding(dst, x.padding)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}
