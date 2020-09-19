package sig

import "io"

// Signer is something capable of signing data.
// User should write all data using Write method and create sign using Sign method.
// Amount of bytes passed per write call does not matter.
type Signer interface {
	io.Writer

	Finalize(appendTo []byte) ([]byte, error)
}

// Verifier checks signs created with signer.
type Verifier interface {
	io.Writer

	Verify(sign []byte) error
}

// GeneratedKeys represents key generated from Keygen.
// Keygens append results to slices contained in this structure.
type GeneratedKeys struct {
	SigningKey   []byte
	VerifyingKey []byte
}

// Keygen creates new key from RNG.
// Dst parameter must not be nil.
type Keygen = func(options interface{}, dst *GeneratedKeys) (err error)

// SigKey is key, which is able to create multiple Signers.
type SigKey = func(options interface{}) (Signer, error)

// VerKey is key, which is able to create multiple Verifiers.
// Each verifier is able to verify single sign.
type VerKey = func(options interface{}) (Verifier, error)

// SigKeyParser parses signing key for some algorithm.
type SigKeyParser func(data []byte) (SigKey, error)

// VerKeyParser prases verifying key for some algorithm.
type VerKeyParser func(data []byte) (VerKey, error)
