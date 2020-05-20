package uciph

import "io"

// SigKeyOptions contains options, which may be used to create signer.
type SigKeyOptions = interface{}

// ParsedSigKey is key, which is able to create multiple Signers.
type ParsedSigKey interface {
	NewEncryptor(options SigKeyOptions) Signer
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

// ParsedDecKey is key, which is able to create multiple Decryptors.
type ParsedVerKey interface {
	NewVerifier(options VerKeyOptions) Verifier
}

type HasherOptions = SigKeyOptions

type ParsedHMACKey interface {
	NewHasher(options HasherOptions) Hasher
}

type Hasher interface {
	io.Writer

	Sum(appendTo []byte) (res []byte, err error)
}