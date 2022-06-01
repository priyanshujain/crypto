// It implements signature utils using rsa
package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/priyanshujain/crypto/hash"
)

type RsaScheme uint

// Rsa schemes
const (
	PKCS1 RsaScheme = 1 + iota // import crypto/md5
	PSS                        // import crypto/sha1
)

// errors
var (
	ErrInvalidSignatureScheme = errors.New("invalid signature scheme")
)

type Rsa struct {
	privateKey *PrivateKey
	publicKey  *PublicKey
	scheme     RsaScheme
	hash       hash.HashType
}

// get standard crypto hash value from hash type like crypto.SHA1 from SHA1
func getStdCryptoHash(htype hash.HashType) (crypto.Hash, error) {
	switch htype {
	case hash.SHA1:
		return crypto.SHA1, nil
	case hash.SHA256:
		return crypto.SHA256, nil
	default:
		return 0, hash.ErrInvalidHashType
	}
}

// sign hashed data using private key
func (x *Rsa) Sign(hashed []byte) ([]byte, error) {
	stdHash, err := getStdCryptoHash(x.hash)
	if err != nil {
		return nil, err
	}
	switch x.scheme {
	case PKCS1:
		return rsa.SignPKCS1v15(rand.Reader, &x.privateKey.Key, stdHash, hashed)
	case PSS:
		return rsa.SignPSS(rand.Reader, &x.privateKey.Key, stdHash, hashed, &rsa.PSSOptions{})
	default:
		return nil, ErrInvalidSignatureScheme
	}
}

// verify hashed data using public key
func (x *Rsa) VerifySignature(hashed []byte, signature []byte) error {
	stdHash, err := getStdCryptoHash(x.hash)
	if err != nil {
		return err
	}
	switch x.scheme {
	case PKCS1:
		return rsa.VerifyPKCS1v15(&x.publicKey.Key, stdHash, hashed, signature)
	case PSS:
		return rsa.VerifyPSS(&x.publicKey.Key, stdHash, hashed, signature, &rsa.PSSOptions{})
	default:
		return ErrInvalidSignatureScheme
	}
}
