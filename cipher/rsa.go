// It implements cipher using RSA algorithm.
package cipher

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/priyanshujain/crypto/hash"
	"github.com/priyanshujain/crypto/keystore"
)

type RsaEncryptionScheme uint

// Rsa schemes
const (
	PKCS1 RsaEncryptionScheme = 1 + iota // https://en.wikipedia.org/wiki/PKCS_1
	OAEP                                 // https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
)

// errors
var (
	ErrInvalidEncryptionScheme = errors.New("invalid encryption scheme")
)

type Rsa struct {
	privateKey *keystore.PrivateKey
	publicKey  *keystore.PublicKey
	scheme     RsaEncryptionScheme
	hash       hash.HashType
}

// rsa encrypt data using public key
func (x *Rsa) Encrypt(src []byte) ([]byte, error) {
	switch x.scheme {
	case PKCS1:
		return rsa.EncryptPKCS1v15(rand.Reader, &x.publicKey.Key, src)
	case OAEP:
		stdHash, err := hash.GetStdCryptoHash(x.hash)
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(stdHash.New(), rand.Reader, &x.publicKey.Key, src, nil)
	default:
		return nil, ErrInvalidEncryptionScheme
	}
}

// rsa encrypt data using private key
func (x *Rsa) Decrypt(src []byte) ([]byte, error) {
	switch x.scheme {
	case PKCS1:
		return rsa.DecryptPKCS1v15(rand.Reader, &x.privateKey.Key, src)
	case OAEP:
		stdHash, err := hash.GetStdCryptoHash(x.hash)
		if err != nil {
			return nil, err
		}
		return (&x.privateKey.Key).Decrypt(rand.Reader, src, &rsa.OAEPOptions{Hash: stdHash})
	default:
		return nil, ErrInvalidEncryptionScheme
	}
}
