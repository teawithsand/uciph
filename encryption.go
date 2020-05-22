package uciph

// ParsedSymmKey is key which is both ParsedEncKey and ParsedDecKey
type ParsedSymmKey interface {
	ParsedEncKey
	ParsedDecKey
}

// EncKeyOptions contains options, which may be used to create encryptor.
type EncKeyOptions = interface{}

// ParsedEncKey is key, which is able to create multiple Encryptors.
type ParsedEncKey interface {
	NewEncryptor(options EncKeyOptions) (Encryptor, error)
}

type ParsedEncKeyFunc func(options EncKeyOptions) (Encryptor, error)

func (f ParsedEncKeyFunc) NewEncryptor(options EncKeyOptions) (Encryptor, error) {
	return f(options)
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

type ParsedDecKeyFunc func(options DecKeyOptions) (Decryptor, error)

func (f ParsedDecKeyFunc) NewDecryptor(options DecKeyOptions) (Decryptor, error) {
	return f(options)
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

	ParseSymmKey(data []byte) (ParsedSymmKey, error)
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

// NonceMode sets how nonces should be generated if cipher needs any.
type NonceMode uint32

const (
	// NonceModeDefault is default nonce mode.
	NonceModeDefault NonceMode = NonceModeRandom

	// NonceModeRandom generates random nonces for specified cipher.
	// It reutrns error if too many ciphertexts are created using this method.
	// For instance for 12 byte nonce limit is 2**32 ciphertexts.
	NonceModeRandom NonceMode = 1

	// NonceModeRandomUnsafe generates random nonce, just like NonceModeRandom
	// but does not fail after some amount of ciphertexts generated.
	//
	// Right now it's not implemented and behaves like NonceModeRandom.
	NonceModeRandomUnsafe NonceMode = 3

	// NonceModeCounter uses NonceCounter in order to generate unique nonces.
	// It returns errors if NonceCouter has overflown and would generate not unique nonces.
	NonceModeCounter NonceMode = 2
)

// NonceModeOptions specifies options, which have NonceMode setting.
type NonceModeOptions interface {
	NonceMode() NonceMode
}

// GetNonceMode gets nonce mode from specified options.
func GetNonceMode(options interface{}) (nm NonceMode) {
	nm = NonceModeDefault
	if nopts, ok := options.(NonceModeOptions); ok {
		nm = nopts.NonceMode()
	}
	return
}
