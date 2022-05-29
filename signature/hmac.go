package signature

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// calculates HMAC signature based on a key and digest algorithm
// supported digest algorithms are: SHA1, 256, 512
func CalculateHmac(key, data []byte, algorithm string) (string, error) {
	digestFunc := getDigestFunc(algorithm)
	if digestFunc == nil {
		err := fmt.Sprintf("unsupported digest algorithm: %s", algorithm)
		return "", errors.New(err)
	}
	h := hmac.New(digestFunc, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// returns a hash function based on a digest algorithm
// we are intentionally not allowing mds here because it is severely compromised
// https://datatracker.ietf.org/doc/html/rfc6151
func getDigestFunc(algorithm string) func() hash.Hash {
	algorithm = strings.ToLower(algorithm)
	switch algorithm {
	case "sha256":
		return sha256.New
	case "sha1":
		return sha1.New
	case "sha512":
		return sha512.New
	default:
		return nil
	}
}
