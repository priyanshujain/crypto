package signature

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/priyanshujain/crypto/hash"
	"github.com/priyanshujain/crypto/keystore"
)

var privateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBuCeEl1Gu4355usZGRnbmYj+NOhKwcam/BeCGeoOaeT5OJmZMy
c4o+iocR6rxj33hN2a2A+abnRT++gIsYRni6t/PDMRLrH+enAWi42GwizE5a6PE2
aoVChxCgBhOkgxDjPDcToBFwa5wx8Q6crJ95lijP3y3BIL3Y6m07ruQA5Yv1D/yI
juoHE8WPLmtIOmNaz4Dq9bSbYsMgjV3W8f/JBaqMmqoMC4AS1dkv0h4n3jTcowvn
gn/i2bN/zea4qMNBmeG8t6gwoN9l7L3Uw9yf/LCi5aHn59UkVQoY576D8CnX/b9s
NSRlODvuSx2jojeE1lHmAd8OeuCiBhUgt+LvAgMBAAECggEAGZJWLjJlLjtZWCQP
ziU3Qkr96ftO+/OIMQ+30GNX9KZNhQaZfHn5QHt01CcWzKbcEEtr1LMvpEMlgyHg
MS3/VHT3Qv8ehGGPtfHP4lT5HEUaWGoV1C2A9mro5CdFXU/QFt6hdgAWzWdUjw6T
9Ljw/pJ0vYoB2gW/2K7x35LPDZ38mCKxnw2J2ZQBx9vvAiKAdi+lV3uN2gyXrhl5
fKAIR5aVsF54i0BlEKRMH7H0uU+pA4NR5NMYJGD4CJzEjJ65C2LfSsHEXt53YPDT
/7vNbPVHeTU8lyf6rMwXFF++S2lPhNV9DGRGa9L/OpzRU14K18gUtS1gqu9Vzpon
h8G6wQKBgQCrP+vO7VjpuOReFc4ghzmaJtleHCtpzvr621E6A+at8kegZvuePSSG
e69mbLegEC1GKy+NqAiQXunXxSDQEy9daDZiNgPO5MpbbIKySgpZKLDWnho9lVIx
+UeGdwIvxAXAL9SR58ob+G+20rRhqyKGmJHJWlCJX1EjSFp8REF5sQKBgQCkfvYX
l0IWpHwQTiX76zw+9GwCFCD4X8dULSUm+5hup91Q/1PtsPdxQKmC7rRavSbbvyDF
AtjBXe4abv0ljKSRnifIC8+7kT6o1FSMJ4WN8SYxP7b0ozDJYO3qXFxz5zi6COVn
+xEgBeOH8C/3KyvpcAAlfH76Tj4iGqMwv4eunwKBgFPXacXXok5bfUMq/c4jJmp4
VreipwaYlXw34B69RjUnhzXa9ZnVaYqGB6vn0kcFZIUUI6YA/KBiN66yDoyQuAHN
QcL3mwmyLfhwudQ8N7DLITkSEtrPvnxFBWWp4mIsYHxlbnc4ulTTXy5tHm8q8C5h
iA7CrudyyTCy/coVSNEhAoGABq8eAtFjnxXp8KOsSXNCjHBUHzWALXd+2v3Gn7Hj
fMOXa54kY+kn9NMi0C4w5+r9tDos87Rs6FaPwUU3RhpT6ZLanPdV5pI9UJDoKpXE
iIL/AUtMfN5Qsi4dHMPKAe+oT27jG3mJNZrnpvNsj4eSjja92sgXRMZ/IdWhQe7W
bZMCgYBTieTkOQKv5yqXtVlgU2HwAYrnq60y9Mnz/LwMTQrKm/oJu7Pv9P6ISLkG
BpBCZXvcsfF4nmCQuv3U3mfig4ubte3wN/6Xln+WZM4/t8KMS9bU8ye4NaIHm666
GCeH9q+NkgOk/a9nS2sOqUvcZKV9MiScIk37p5pAcLH0Agg6RQ==
-----END RSA PRIVATE KEY-----`

var rsaSignatureTestCases = []struct {
	name   string
	in     string
	out    string
	scheme RsaScheme
	htype  hash.HashType
}{
	{
		name:   "PKCS1-SHA256",
		in:     "test",
		out:    "2db263532ee6f5b3894471797eccb3a2d041bd3d0e381ceb861a679830a3811cb39da5f89e86b4269b14669dac38a7efde01d7eb6ec9e4a6ee6b05908fcb08312baceae8d40f74c0e71e62654664e9b283b6523d458a461c202a257859fe40800a05767d4df12d18818f0a70d4eecb0753f7888a21acb575d01ae368a0e414d76573508d6061af744a8136797f69beff74d96a1ece16914bdb2f4b4e7578d20861b2edbd3a13216dc7db5bb168553354eca1a1b4c88bf9b2709431c6451435ff51d65ff6d8b549eacc0dde90667ab6cf65337123a73f86f936a344e0207da18a09e703bf17b84984fbae5685370da051ec44072e0d12a38b137dd2554d21c905",
		scheme: PKCS1,
		htype:  hash.SHA256,
	},
	{
		name:   "PKCS1-SHA1",
		in:     "This is a SHA sign test",
		out:    "1454d27626995a26d549407285aa8990c6ddf365bfc786dbdd5a7d3f5a268d77e638359d60b31461ff6fbe22a2c7d8905d917225da5e71efb29dc4a2ede74f84c4c3120cce9044b2640ce992588fefc8cb1c24d9078fdd1653fc1402f32a8e0fd174ed015e9287ec1c970d5ffe401be2f80abb783fb70400547a4bf5f2e8ffbdeff2541013e2a3d77073a8108e44cd109d71e6793763b37f8b908d04b9fc90f091799f550e4b15cc14ce1c55b7cee3333fe96503ac4c203f36165f9fa818700e791ddb649c5c9eefb0a72fa1f3960612bf4852818447b1f36dd1ea1f9bff9a1a1153311e316f126738a1bb0cef427fe0b1031fa274cd1e56bd486603b24c663b",
		scheme: PKCS1,
		htype:  hash.SHA1,
	},
	{
		name:   "PSS-SHA1",
		in:     "This is a PSS sign test",
		out:    "",
		scheme: PSS,
		htype:  hash.SHA1,
	},
}

func TestPKCS1RsaSignature(t *testing.T) {
	rsaPrivateKey, _ := keystore.ParsePrivateKeyFromPem([]byte(privateKeyPem))
	for _, test := range rsaSignatureTestCases {
		if test.scheme != PKCS1 {
			continue
		}
		t.Run(fmt.Sprintf("RSA-Sign: %s:", test.name), func(t *testing.T) {
			digest, err := hash.Hash(test.htype, []byte(test.in))
			if err != nil {
				t.Errorf("RsaSign(%s) failed due to Hash: %s", test.in, err)
			}

			rsa := Rsa{privateKey: rsaPrivateKey, publicKey: rsaPrivateKey.PublicKey(), hash: test.htype, scheme: test.scheme}
			sig, err := rsa.Sign(digest)
			if err != nil {
				t.Errorf("RsaSign(%s) failed: %s", test.in, err)
			}
			signHex := hex.EncodeToString(sig)
			if signHex != test.out {
				t.Errorf("RsaSign(%s) = %s, want %s", string(digest), signHex, test.out)
			}
			err = rsa.VerifySignature(digest, sig)
			if err != nil {
				t.Errorf("TestPKCS1RsaSignature: RsaVerifySignature(%s) failed: %s", test.in, err)
			}
		})
	}
}

func TestPSSRsaSignature(t *testing.T) {
	rsaPrivateKey, _ := keystore.ParsePrivateKeyFromPem([]byte(privateKeyPem))
	for _, test := range rsaSignatureTestCases {
		if test.scheme != PSS {
			continue
		}
		t.Run(fmt.Sprintf("RSA-Sign: %s:", test.name), func(t *testing.T) {
			digest, err := hash.Hash(test.htype, []byte(test.in))
			if err != nil {
				t.Errorf("RsaSign(%s) failed due to Hash: %s", test.in, err)
			}

			rsa := Rsa{privateKey: rsaPrivateKey, publicKey: rsaPrivateKey.PublicKey(), hash: test.htype, scheme: test.scheme}
			sign, err := rsa.Sign(digest)
			if err != nil {
				t.Errorf("RsaSign(%s) failed: %s", test.in, err)
			}
			err = rsa.VerifySignature(digest, sign)
			if err != nil {
				t.Errorf("TestPSSRsaSignature: RsaVerifySignature(%s) failed: %s", test.in, err)
			}
		})
	}
}
