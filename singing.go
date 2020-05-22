package uciph

import "io"

// SigKeyOptions contains options, which may be used to create signer.
type SigKeyOptions = interface{}

// ParsedSigKey is key, which is able to create multiple Signers.
type ParsedSigKey interface {
	NewEncryptor(options SigKeyOptions) (Signer, error)
}

// Signer is something capable of signing data.
// User should write all data using Write method and create sign using Sign method.
// Amount of bytes passed per write call does not matter.
type Signer interface {
	io.Writer

	Sign(appendTo []byte) ([]byte, error)
}

// VerKeyOptions contains options, which may be used to create decryptor.
type VerKeyOptions = SigKeyOptions

// Verifier is able to verify signs created by signer.
type Verifier interface {
	io.Writer

	CheckSign(sign []byte) error
}

// ParsedVerKey is key, which is able to create multiple Verifiers.
// Each verifier is able to verify sign for single data.
type ParsedVerKey interface {
	NewVerifier(options VerKeyOptions) (Verifier, error)
}

// HasherOptions contains options, which are passed to hasher.
type HasherOptions = SigKeyOptions

// HMACKeyParser is something capable of creating HMAC key.
type HMACKeyParser interface {
	ParseHMACKey(data []byte) (ParsedHMACKey, error)
}

// HMACKeyParserFunc is function, which satisfies HMACKeyParser.
type HMACKeyParserFunc func(data []byte) (ParsedHMACKey, error)

// ParseHMACKey makes HMACKeyParserFunc satisfy HMACKeyParser
func (f HMACKeyParserFunc) ParseHMACKey(data []byte) (ParsedHMACKey, error) {
	return f(data)
}

// ParsedHMACKey is HMAC key, which is able to create new hashers.
type ParsedHMACKey interface {
	NewHasher(options HasherOptions) (Hasher, error)
}

// ParsedHMACKeyFunc is function, which staisfies ParsedHMACKey.
type ParsedHMACKeyFunc func(options HasherOptions) (Hasher, error)

// NewHasher makes ParsedHMACKeyFunc satisfy ParsedHMACKey.
func (f ParsedHMACKeyFunc) NewHasher(options HasherOptions) (Hasher, error) {
	return f(options)
}

// Hasher is something capable of computing hashes.
// It accepts data and creates hash sum form it.
type Hasher interface {
	io.Writer

	Sum(appendTo []byte) (res []byte, err error)
}

// HasherFactory is something, which creates hasher
// but are not HMAC keys.
type HasherFactory interface {
	NewHasher(options HasherOptions) (Hasher, error)
}

// HasherFactoryFunc is something capa
type HasherFactoryFunc func(options HasherOptions) (Hasher, error)

func (f HasherFactoryFunc) NewHasher(options HasherOptions) (Hasher, error) {
	return f(options)
}
