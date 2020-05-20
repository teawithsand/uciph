package uciph

// EncKeyOptions contains options, which may be used to create encryptor.
type EncKeyOptions = interface{}

// ParsedEncKey is key, which is able to create multiple Encryptors.
type ParsedEncKey interface {
	NewEncryptor(options EncKeyOptions) Encryptor
}

// Encryptor is something capable of encrypting data.
// It works in either chunk-by-chunk mode, where sizes of in argument during subsequent calls matter
// and stream mode, which do not apply that restriction.
type Encryptor interface {
	Encrypt(in, appendTo []byte) (res []byte, err error)
}

type EncryptorFunc func(in, appendTo []byte) (res []byte, err error)
func(f EncryptorFunc) Encrypt(in, appendTo []byte) (res []byte, err error){
	return f(in, appendTo)
}

// DecKeyOptions contains options, which may be used to create decryptor.
type DecKeyOptions = EncKeyOptions

// Decryptor is able to reverse transformation done by Encryptor.
type Decryptor interface {
	Decrypt(in, appendTo []byte) (res []byte, err error)
}

type DecryptorFunc func(in, appendTo []byte) (res []byte, err error)
func(f DecryptorFunc) Decrypt(in, appendTo []byte) (res []byte, err error){
	return f(in, appendTo)
}

// ParsedDecKey is key, which is able to create multiple Decryptors.
type ParsedDecKey interface {
	NewDecryptor(options DecKeyOptions) Decryptor
}