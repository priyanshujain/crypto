package cipher

import (
	"bytes"
	"crypto/aes"
	"errors"
)

// Most modern cryptographic hash functions process messages in fixed-length blocks;
// all but the earliest hash functions include some sort of padding scheme.
// It is critical for cryptographic hash functions to employ termination schemes that
// prevent a hash from being vulnerable to length extension attacks.

// pkcs7 right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
// `pkcs5` padding is identical to `pkcs7` padding, except that it has only been defined
// for block ciphers that use a 64-bit (8-byte) block size. In practice the two can be used interchangeably.

// padding errors.
var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidData indicates bad input to pad or unpad.
	ErrInvalidData = errors.New("invalid data")

	// ErrInvalidPadding indicates unpad fails to bad input.
	ErrInvalidPadding = errors.New("invalid padding on input")

	// ErrInvalidBlockSizePKCS5 indicates that a 64-bit (8-byte) block size is required for PKCS5 padding.
	ErrInvalidBlockSizePKCS5 = errors.New("invalid blocksize for pkcs5")

	// ErrUnsupportedPadding indicates that the padding scheme is not supported.
	ErrUnsupportedPadding = errors.New("unsupported padding scheme")
)

func pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 {
		return nil, ErrInvalidBlockSize
	}
	if len(src) == 0 {
		return nil, ErrInvalidData
	}
	padLength := blockSize - (len(src) % blockSize)
	if padLength == 0 {
		padLength = blockSize
	}
	padding := bytes.Repeat([]byte{byte(padLength)}, padLength)
	return append(src, padding...), nil
}

// unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func unpad(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 {
		return nil, ErrInvalidBlockSize
	}
	if len(src) == 0 {
		return nil, ErrInvalidData
	}
	if len(src)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	// the last byte is the length of padding
	padLength := int(src[len(src)-1])
	if padLength > len(src) {
		return nil, ErrInvalidPadding
	}

	// check padding integrity, zero-byte is not allowed, all bytes should be the same
	padding := src[len(src)-padLength:]
	for _, padByte := range padding {
		if padByte != byte(padLength) {
			return nil, ErrInvalidPadding
		}
	}
	return src[:len(src)-padLength], nil
}

// PKCS5 padding.
func PkCS5Padding(src []byte, blockSize int) ([]byte, error) {
	if blockSize != 8 {
		return nil, ErrInvalidBlockSizePKCS5
	}
	return pad(src, blockSize)
}

// PKCS5 un-padding.
func PkCS5UnPadding(src []byte, blockSize int) ([]byte, error) {
	if blockSize != 8 {
		return nil, ErrInvalidBlockSizePKCS5
	}
	return unpad(src, blockSize)
}

// PKCS7 padding.
func PkCS7Padding(src []byte, blockSize int) ([]byte, error) {
	return pad(src, blockSize)
}

// PKCS7 un-padding.
func PkCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	return unpad(src, blockSize)
}

// padding algorithms
// supported: PKCS5, PKCS7
func AddPadding(src []byte, padding AesPaddingScheme) (padText []byte, err error) {
	switch padding {
	case PKCS5:
		padText, err = PkCS5Padding(src, aes.BlockSize)
	case PKCS7:
		padText, err = PkCS7Padding(src, aes.BlockSize)
	default:
		return nil, ErrUnsupportedPadding
	}
	if err != nil {
		return nil, err
	}
	return padText, nil
}

// Remove extra padding from decrypted text
func TrimPadding(src []byte, padding AesPaddingScheme) (padText []byte, err error) {
	switch padding {
	case PKCS5:
		padText, err = PkCS5UnPadding(src, aes.BlockSize)
	case PKCS7:
		padText, err = PkCS7UnPadding(src, aes.BlockSize)
	default:
		return nil, ErrUnsupportedPadding
	}
	if err != nil {
		return nil, err
	}
	return padText, nil
}
