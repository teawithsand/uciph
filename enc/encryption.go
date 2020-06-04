package enc

// SymKey is key which is both EncKey and DecKey
type SymKey interface {
	EncKey
	DecKey
}

// EncKey is key, which is able to create multiple Encryptors.
type EncKey interface {
	NewEncryptor(options interface{}) (Encryptor, error)
}

// EncKeyFunc is function, which is valid encryption key.
type EncKeyFunc func(options interface{}) (Encryptor, error)

// NewEncryptor makes EncKeyFunc satisfy EncKey.
func (f EncKeyFunc) NewEncryptor(options interface{}) (Encryptor, error) {
	return f(options)
}

// EncKeyParser parses encryption key.
type EncKeyParser interface {
	ParseEncKey(data []byte) (EncKey, error)
}

// KeyParserFunc is function which is EncKeyParser.
type KeyParserFunc func(data []byte) (EncKey, error)

// ParseEncKey makes EncKeyParserFunc satisfy ParseEncKey.
func (f KeyParserFunc) ParseEncKey(data []byte) (EncKey, error) {
	return f(data)
}

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

// DecKey is key, which is able to create multiple Decryptors.
type DecKey interface {
	NewDecryptor(options interface{}) (Decryptor, error)
}

// DecKeyFunc is function which is DecKey.
type DecKeyFunc func(options interface{}) (Decryptor, error)

// NewDecryptor makes DecKeyFunc satisfy DecKey.
func (f DecKeyFunc) NewDecryptor(options interface{}) (Decryptor, error) {
	return f(options)
}

// DecKeyParser is able to parse decryption keys.
type DecKeyParser interface {
	ParseDecKey(data []byte) (DecKey, error)
}

// DecKeyParserFunc is function which is DecKeyParser.
type DecKeyParserFunc func(data []byte) (DecKey, error)

// ParseDecKey makes DecKeyParserFunc satisfy DecKeyParser.
func (f DecKeyParserFunc) ParseDecKey(data []byte) (DecKey, error) {
	return f(data)
}

// SymKeyParser is parser, which parses symmetric key.
// Symmetric key is used for both encryption and decryption, thus same code can be used to handle parsing.
type SymKeyParser interface {
	EncKeyParser
	DecKeyParser

	ParseSymKey(data []byte) (SymKey, error)
}

// SymEncKeygen generates symmetric encryption keys.
type SymEncKeygen interface {
	GenSymmKey(options interface{}, appendTo []byte) (res []byte, err error)
}

//SymEncKeygenFunc is function which is SymEncKeygen.
type SymEncKeygenFunc func(options interface{}, appendTo []byte) (res []byte, err error)

// GenSymmKey makes SymmEncKeygenFunc satisfy SymEncKeygen.
func (f SymEncKeygenFunc) GenSymmKey(options interface{}, appendTo []byte) (res []byte, err error) {
	return f(options, appendTo)
}

// AsymEncKeygen generates asymmteric encryption/decryption keypairs
type AsymEncKeygen interface {
	GenAsymKey(options interface{}, encAppendTo, decAppendTo []byte) (encryption, decryption []byte, err error)
}

// AsymKeygenFunc is function which is AsymEncKeygen.
type AsymKeygenFunc func(options interface{}) (encryption, decryption []byte, err error)

// GenAsymKey makes AsymKeygenFunc satisfy AsymEncKeygen.
func (f AsymKeygenFunc) GenAsymKey(options interface{}) (encryption, decryption []byte, err error) {
	return f(options)
}
