package cipher

// AES encryption
// Input: mode, padding, key, initialization vector, plaintext
// output cipherText

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// Aes Block cipher mode of operation
type AesBlockMode uint

const (
	CFB AesBlockMode = 1 + iota // https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
	CTR                         // https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
	CBC                         // https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
)

// supported padding schemes
type AesPaddingScheme uint

const (
	PKCS5 AesPaddingScheme = 1 + iota // https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
	PKCS7
)

type Aes struct {
	key     []byte
	iv      []byte
	mode    AesBlockMode
	padding AesPaddingScheme
}

// Errors
var (
	// ErrShortBlock indicates when cipher size is less than block size of AES
	ErrShortBlock = errors.New("cipher text too short")

	// ErrUnsupportedMode indicates when mode is not supported
	ErrUnsupportedMode = errors.New("unsupported aes mode")
)

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

// encrypts bytes array into bytes array
func (x *Aes) Encrypt(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(x.key)
	if err != nil {
		return nil, err
	}
	if x.padding != 0 {
		src, err = AddPadding(src, x.padding)
		if err != nil {
			return nil, err
		}
	}
	dst := make([]byte, len(src))
	switch x.mode {
	case CFB:
		x.cfbEncrypt(block, src, dst)
	case CTR:
		x.ctrEncrypt(block, src, dst)
	case CBC:
		x.cbcEncrypt(block, src, dst)
	default:
		return nil, ErrUnsupportedMode
	}
	return dst, nil
}

// decrypts bytes array into bytes array
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
	case CFB:
		x.cfbDecrypt(block, src, dst)
	case CTR:
		x.ctrDecrypt(block, src, dst)
	case CBC:
		x.cbcDecrypt(block, src, dst)
	default:
		return nil, ErrUnsupportedMode
	}

	if x.padding != 0 {
		dst, err = TrimPadding(dst, x.padding)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// AES encryption with string input and output in base64
func (x *Aes) EncryptBase64(src string) (string, error) {
	dst, err := x.Encrypt([]byte(src))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(dst), nil
}

// AES decryption with input in base64 and string output
func (x *Aes) DecryptBase64(src string) (string, error) {
	dst, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}
	dst, err = x.Decrypt(dst)
	if err != nil {
		return "", err
	}
	return string(dst), nil
}
