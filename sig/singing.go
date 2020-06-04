package sig

import (
	"io"
)

// KeyParser is both SigKeyParser and VerKeyParser.
type KeyParser interface {
	SigKeyParser
	VerKeyParser
}

// SigKeygen generates signing key.
type SigKeygen interface {
	GenSigKey(options interface{}, vkAppendTo, skAppendTo []byte) (vk, sk []byte, err error)
}

// SigKeygenFunc is function, which satisifies SigKeygen interface.
type SigKeygenFunc func(options interface{}, vkAppendTo, skAppendTo []byte) (pk, sk []byte, err error)

// GenSigKey makes SigKeygenFunc satisfy SigKeygen.
func (f SigKeygenFunc) GenSigKey(options interface{}, vkAppendTo, skAppendTo []byte) (pk, sk []byte, err error) {
	return f(options, vkAppendTo, skAppendTo)
}

// SigKey is key, which is able to create multiple Signers.
type SigKey interface {
	NewSigner(options interface{}) (Signer, error)
}

// SigKeyParser parses signing key.
type SigKeyParser interface {
	ParseSigKey(data []byte) (SigKey, error)
}

// Signer is something capable of signing data.
// User should write all data using Write method and create sign using Sign method.
// Amount of bytes passed per write call does not matter.
type Signer interface {
	io.Writer

	Sign(appendTo []byte) ([]byte, error)
}

// Verifier is able to verify signs created by signer.
type Verifier interface {
	io.Writer

	Verify(sign []byte) error
}

// VerKey is key, which is able to create multiple Verifiers.
// Each verifier is able to verify sign for single data.
type VerKey interface {
	NewVerifier(options interface{}) (Verifier, error)
}

// TODO(teawithsand): better name for SigVerKeyParser?

// SigVerKeyParser is parser, which parses both signing and verifying keys.
type SigVerKeyParser interface {
	SigKeyParser
	VerKeyParser
}

// VerKeyParser parses verification keys.
type VerKeyParser interface {
	ParseVerKey(data []byte) (VerKey, error)
}

// MACKeyParser is something capable of creating HMAC key.
type MACKeyParser interface {
	ParseMACKey(data []byte) (MACKey, error)
}

// MACKeyParserFunc is function, which satisfies MACKeyParser.
type MACKeyParserFunc func(data []byte) (MACKey, error)

// ParseMACKey makes MACKeyParserFunc satisfy MACKeyParser
func (f MACKeyParserFunc) ParseMACKey(data []byte) (MACKey, error) {
	return f(data)
}

// MACKey is HMAC key, which is able to create new hashers.
type MACKey interface {
	NewHasher(options interface{}) (Hasher, error)
}

// MACKeyFunc is function, which staisfies MACKey.
type MACKeyFunc func(options interface{}) (Hasher, error)

// NewHasher makes MACKeyFunc satisfy MACKey.
func (f MACKeyFunc) NewHasher(options interface{}) (Hasher, error) {
	return f(options)
}

// Hasher is something capable of computing hashes.
// It accepts data and creates hash sum form it.
type Hasher interface {
	io.Writer

	Sum(appendTo []byte) (res []byte, err error)
}

// HasherFac is something, which creates hasher
// but are not HMAC keys.
type HasherFac interface {
	NewHasher(options interface{}) (Hasher, error)
}

// HasherFacFunc is function which is HasherFac.
type HasherFacFunc func(options interface{}) (Hasher, error)

// NewHasher makes HasherFacFunc satisfy HasherFac.
func (f HasherFacFunc) NewHasher(options interface{}) (Hasher, error) {
	return f(options)
}
