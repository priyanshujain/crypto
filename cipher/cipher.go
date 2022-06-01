// package cipher implements block cipher algorithms with different modes.
// It supports AES.

package cipher

type BlockMode interface {
	Encrypt(plainText []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
}
