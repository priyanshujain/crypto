// hash package implements hash functions.
// It currently supports SHA1, SHA256.
package hash

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
)

type HashType uint

// types of supported hashing algorithms
const (
	SHA1   HashType = 1 + iota // http://en.wikipedia.org/wiki/SHA-1
	SHA256                     // https://en.wikipedia.org/wiki/SHA-2
)

// errors
var (
	ErrInvalidHashType = errors.New("invalid hash type")
)

// get standard crypto hash value from hash type like crypto.SHA1 from SHA1
func GetStdCryptoHash(htype HashType) (crypto.Hash, error) {
	switch htype {
	case SHA1:
		return crypto.SHA1, nil
	case SHA256:
		return crypto.SHA256, nil
	default:
		return 0, ErrInvalidHashType
	}
}

// Hash hashes data using a given hash algorithm
func Hash(htype HashType, src []byte) ([]byte, error) {
	var h hash.Hash
	switch htype {
	case SHA1:
		h = sha1.New()
	case SHA256:
		h = sha256.New()
	default:
		return nil, ErrInvalidHashType
	}
	h.Write(src)
	return h.Sum(nil), nil
}

// HashString hashes a string using a given hash algorithm into a hex string
func HashHex(hashType HashType, src []byte) (string, error) {
	dst, err := Hash(hashType, src)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dst), nil
}

// HashString hashes a string using a given hash algorithm into a bas64 string
func HashBase64(hashType HashType, src []byte) (string, error) {
	dst, err := Hash(hashType, src)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(dst), nil
}
