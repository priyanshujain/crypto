// It implements signature utils using rsa
package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/priyanshujain/crypto/hash"
	"github.com/priyanshujain/crypto/keystore"
)

type RsaScheme uint

// Rsa schemes
const (
	PKCS1 RsaScheme = 1 + iota // https://en.wikipedia.org/wiki/PKCS_1
	PSS                        // https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
)

// errors
var (
	ErrInvalidSignatureScheme = errors.New("invalid signature scheme")
)

type Rsa struct {
	privateKey *keystore.PrivateKey
	publicKey  *keystore.PublicKey
	scheme     RsaScheme
	hash       hash.HashType
}

// sign hashed data using private key
func (x *Rsa) Sign(hashed []byte) ([]byte, error) {
	stdHash, err := hash.GetStdCryptoHash(x.hash)
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
	stdHash, err := hash.GetStdCryptoHash(x.hash)
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
