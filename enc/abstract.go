package enc

import "io"

// Encryptor is something capable of encrypting data.
// It works in either chunk-by-chunk mode, where sizes of in argument during subsequent calls matter
// and stream mode, which do not apply that restriction.
type Encryptor interface {
	Encrypt(in, appendTo []byte) (res []byte, err error)
}

// EncryptorFunc is func, which is encrpytor.
type EncryptorFunc func(in, appendTo []byte) (res []byte, err error)

// Encrypt makes EncryptorFunc satisfy Encryptor.
func (f EncryptorFunc) Encrypt(in, appendTo []byte) (res []byte, err error) {
	return f(in, appendTo)
}

// Decryptor is able to reverse transformation done by Encryptor.
type Decryptor interface {
	Decrypt(in, appendTo []byte) (res []byte, err error)
}

// DecryptorFunc is function which is Decryptor.
type DecryptorFunc func(in, appendTo []byte) (res []byte, err error)

// Decrypt makes DecryptorFunc satisfy Decryptor.
func (f DecryptorFunc) Decrypt(in, appendTo []byte) (res []byte, err error) {
	return f(in, appendTo)
}

// EncKey represents single encryption key, either symmetric or asymmetric.
type EncKey = func(options interface{}) (Encryptor, error)

// DecKey represents single decryption key.
type DecKey = func(options interface{}) (Decryptor, error)

type GeneratedKeys struct {
	Encryption []byte
	Decryption []byte
}

// SymmKeygen creates symmetric encryption key from RNG.
type SymmKeygen func(options interface{}, dst []byte) (res []byte, err error)

// AsymmKeygen creates asymmetric encryption/decryption keys from RNG.
type AsymmKeygen func(options interface{}, dst *GeneratedKeys) (err error)

// SymmKeyParser parses symmetric key for some algorithm.
type SymmKeyParser func(data []byte) (EncKey, DecKey, error)

// EncKeyParser prases encryption key for some algorithm.
type EncKeyParser func(data []byte) (EncKey, error)

// DecKeyParser prases decryption key for some algorithm.
type DecKeyParser func(data []byte) (EncKey, error)

// StreamEncryptor is encryptor, which processes data in streamming manner.
// It has to be closed in order to flush rest of data, since StreamEncryptor may do buffering.
type StreamEncryptor interface {
	io.WriteCloser
}

// StreamDecryptor is decryptor, which processes data in streamming manner.
// StreamDecryptor is guaranteed to find error once some occured.
// It MAY NOT be able to find out that chunks are reordered or truncated.
// This property is implementation-dependent.
// If StreamDecryptor implements it, truncated error will be returned on close.
type StreamDecryptor interface {
	io.ReadCloser
}
