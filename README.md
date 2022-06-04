# crypto

simplified crypto module using go crypto library. We are not implementing any crypto algorithms on our own but taking it 
from NIST approved implementation and providing an easy interface to use them.

[![Go Reference](https://pkg.go.dev/badge/github.com/priyanshujain/crypto.svg)](https://pkg.go.dev/github.com/priyanshujain/crypto)
[![Test Status](https://github.com/priyanshujain/crypto/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/priyanshujain/crypto/actions)
[![codecov](https://codecov.io/gh/priyanshujain/crypto/branch/master/graph/badge.svg?token=8UY0NTGGRM)](https://codecov.io/gh/priyanshujain/crypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/priyanshujain/crypto)](https://goreportcard.com/report/github.com/priyanshujain/crypto)

## Install

```
go get github.com/priyanshujain/crypto
```

## Testing

1. perform tests
```
make test
```

2. produces coverage
```
make cover
```

3. run go vet linter
```
make lint
```

## Packages 
1. cipher: It includes both symmetric(AES) and asymmetric(RSA) key encryption.

2. signature: It includes signature algorithms like HMAC, RSA etc.

3. hash: It has common hash functions including SHA1 and SHA256.

4. Keystore: It implements key store and key generation for common cryptographic algorithms.


### cipher

#### AES


It support the following modes of operations
1. CBC (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
2. CTR (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))
3. CFB (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB))

and the following padding schemes
1. PKCS5 (https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7)
2. PKCS7

#### RSA

It supports the following encryption schemes
1. PKCS1 (https://datatracker.ietf.org/doc/html/rfc3447)
2. OAEP (https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)

### signature

#### RSA
It supports the following signature schemes
1. PKCS1 (https://en.wikipedia.org/wiki/PKCS_1)
2. PSS (https://en.wikipedia.org/wiki/Probabilistic_signature_scheme)

## Notes

1. It uses pem format for all public key infrastructure. 