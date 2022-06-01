// keys imports or create keys for public key infrastructure
// it by default uses pem format for all keys
package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type PrivateKey struct {
	Key rsa.PrivateKey
}

type PublicKey struct {
	Key rsa.PublicKey
}

// PublicKey returns the public key from a private key in *PublicKey format
func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{Key: k.Key.PublicKey}
}

// generate a key pair given bits size
// It uses multi prime RSA key generation algorithm with number of primes as 2
// GenerateMultiPrimeKey(random, 2, bits)
// https://cacr.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
func GenerateKeyPair(bits int) (*PrivateKey, *PublicKey, error) {
	// generate key pair
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return &PrivateKey{Key: *key}, &PublicKey{Key: key.PublicKey}, nil
}

// ParsePrivateKeyFromPem parses a private key from pem format
func ParsePrivateKeyFromPem(pemBytes []byte) (*PrivateKey, error) {
	// parse private key from pem format
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		block, _ = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("failed to parse private key")
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{Key: *key}, nil
}

// ParsePublicKeyFromPem parses a public key from pem format
func ParsePublicKeyFromPem(pemBytes []byte) (*PublicKey, error) {
	// parse public key from pem format
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to parse public key")
	}
	return &PublicKey{Key: *rsaKey}, nil
}

// ConvertPrivateKeyToPem creates a private key to pem format
// (https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
func ConvertPrivateKeyToPem(k *PrivateKey) []byte {
	// convert private key to pem format
	pubKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&k.Key),
	})
	// strip last newline
	pubKey = pubKey[:len(pubKey)-1]
	return pubKey
}

// ConvertPublicKeyToPem creates a public key to pem format
// (https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
func ConvertPublicKeyToPem(k *PublicKey) []byte {
	// convert public key to pem format
	pubKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&k.Key),
	})
	// strip last newline
	pubKey = pubKey[:len(pubKey)-1]
	return pubKey
}
