package sig

import (
	"bytes"
	"crypto/ed25519"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
)

type ed25519SigKey [ed25519.PrivateKeySize]byte

type ed25519VerKey [ed25519.PublicKeySize]byte

// Ed25519Keygen generates Ed25519Keys
func Ed25519Keygen(options interface{}, dst *GeneratedKeys) (err error) {
	if dst == nil {
		panic("uciph/sig: nil *GeneratedKeys provided to GenerateEd25519Keys")
	}

	rng := rand.GetRNG(options)
	rpk, rsk, err := ed25519.GenerateKey(rng)
	if err != nil {
		return
	}

	dst.VerifyingKey = append(dst.VerifyingKey, rpk...)
	dst.SigningKey = append(dst.SigningKey, rsk...)
	return
}

// ParseEd25519SigKey parses signing key for Ed25519 signing algorithm.
func ParseEd25519SigKey(data []byte) (SigKey, error) {
	var sk ed25519SigKey
	if len(sk) != len(data) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(sk[:], data)

	return func(options interface{}) (Signer, error) {
		hasher, err := GetSigningHasher(options)
		if err != nil {
			return nil, err
		}
		doSign := func(data, appendTo []byte) (res []byte, err error) {
			sign := ed25519.Sign(ed25519.PrivateKey(sk[:]), data)
			res = append(appendTo, sign...)
			return
		}
		if hasher != nil {
			return &hashSigner{
				hasher: hasher,
				doSign: doSign,
			}, nil
		}

		return &bufferSigner{
			buf:    bytes.NewBuffer(nil),
			doSign: doSign,
		}, nil
	}, nil

}

// ParseEd25519VerKey parses signing key for Ed25519 signing algorithm.
func ParseEd25519VerKey(data []byte) (VerKey, error) {
	var vk ed25519VerKey
	if len(vk) != len(data) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(vk[:], data)

	return func(options interface{}) (Verifier, error) {
		hasher, err := GetSigningHasher(options)
		if err != nil {
			return nil, err
		}
		doVerify := func(data, sign []byte) error {
			if !ed25519.Verify(ed25519.PublicKey(vk[:]), data, sign) {
				return uciph.ErrSignInvalid
			}
			return nil
		}
		if hasher != nil {
			return &hashVerifier{
				hasher:   hasher,
				doVerify: doVerify,
			}, nil
		}

		return &bufferVerifier{
			buf:      bytes.NewBuffer(nil),
			doVerify: doVerify,
		}, nil
	}, nil
}
