package uciph

// EncKeyOptions contains options, which may be used to create encryptor.
type EncKeyOptions = interface{}

// ParsedEncKey is key, which is able to create multiple Encryptors.
type ParsedEncKey interface {
	NewEncryptor(options EncKeyOptions) (Encryptor, error)
}

type EncKeyParser interface {
	ParseEncKey(data []byte) (ParsedEncKey, error)
}

type EncKeyParserFunc func(data []byte) (ParsedEncKey, error)

func (f EncKeyParserFunc) ParseEncKey(data []byte) (ParsedEncKey, error) {
	return f(data)
}

// Encryptor is something capable of encrypting data.
// It works in either chunk-by-chunk mode, where sizes of in argument during subsequent calls matter
// and stream mode, which do not apply that restriction.
type Encryptor interface {
	Encrypt(in, appendTo []byte) (res []byte, err error)
}

type EncryptorFunc func(in, appendTo []byte) (res []byte, err error)

func (f EncryptorFunc) Encrypt(in, appendTo []byte) (res []byte, err error) {
	return f(in, appendTo)
}

// DecKeyOptions contains options, which may be used to create decryptor.
type DecKeyOptions = EncKeyOptions

// Decryptor is able to reverse transformation done by Encryptor.
type Decryptor interface {
	Decrypt(in, appendTo []byte) (res []byte, err error)
}

type DecryptorFunc func(in, appendTo []byte) (res []byte, err error)

func (f DecryptorFunc) Decrypt(in, appendTo []byte) (res []byte, err error) {
	return f(in, appendTo)
}

// ParsedDecKey is key, which is able to create multiple Decryptors.
type ParsedDecKey interface {
	NewDecryptor(options DecKeyOptions) (Decryptor, error)
}

type DecKeyParser interface {
	ParseDecKey(data []byte) (ParsedDecKey, error)
}

type DecKeyParserFunc func(data []byte) (ParsedDecKey, error)

func (f DecKeyParserFunc) ParseDecKey(data []byte) (ParsedDecKey, error) {
	return f(data)
}

// SymmKeyParser is parser, which parses symmetric key.
// Symmetric key is used for both encryption and decryption, thus same code can be used to handle parsing.
type SymmKeyParser interface {
	EncKeyParser
	DecKeyParser
}

type KeygenOptions = interface{}

type SymmEncKeygen interface {
	GenSymmKey(options KeygenOptions) (data []byte, err error)
}
type SymmEncKeygenFunc func(options KeygenOptions) (data []byte, err error)

func (f SymmEncKeygenFunc) GenSymmKey(options KeygenOptions) (data []byte, err error) {
	return f(options)
}

type AsymEncKeygen interface {
	GenAsymKey(options KeygenOptions) (encryption, decryption []byte, err error)
}
type AsymEncKeygenFunc func(options KeygenOptions) (encryption, decryption []byte, err error)

func (f AsymEncKeygenFunc) GenAsymKey(options KeygenOptions) (encryption, decryption []byte, err error) {
	return f(options)
}
