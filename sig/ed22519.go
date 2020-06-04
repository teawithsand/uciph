package sig

import (
	"bytes"
	"crypto/ed25519"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
)

var ed25519KeyParser = ed25519parser{}

// Ed25519KeyParser is parser for both signing and verifying key parsers.
func Ed25519KeyParser() SigKeyParser {
	return ed25519KeyParser
}

var ed25519Keygen = SigKeygenFunc(func(options interface{}, vkAppendTo, skAppendTo []byte) (vk, sk []byte, err error) {
	rng := rand.GetRNG(options)
	rpk, rsk, err := ed25519.GenerateKey(rng)
	if err != nil {
		return
	}

	vkAppendTo = append(vkAppendTo, rpk...)
	skAppendTo = append(skAppendTo, rsk...)
	return
})

// Ed25519Keygen generates ed25519 signing key pair.
func Ed25519Keygen() SigKeygen {
	return ed25519Keygen
}

type ed25519parser struct{}

type ed25519SigKey [ed25519.PrivateKeySize]byte

type ed25519VerKey [ed25519.PublicKeySize]byte

// ParseSigKey parses signing key.
func (ed25519parser) ParseSigKey(data []byte) (SigKey, error) {
	var sk ed25519SigKey
	if len(sk) != len(data) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(sk[:], data)
	return sk, nil
}

// ParseVerKey parses verifying key.
func (ed25519parser) ParseVerKey(data []byte) (VerKey, error) {
	var vk ed25519VerKey
	if len(vk) != len(data) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(vk[:], data)
	return vk, nil
}

func (k ed25519SigKey) NewSigner(options interface{}) (Signer, error) {
	hasher, err := GetSigningHasher(options)
	if err != nil {
		return nil, err
	}
	doSign := func(data, appendTo []byte) (res []byte, err error) {
		sign := ed25519.Sign(ed25519.PrivateKey(k[:]), data)
		res = append(appendTo, sign...)
		return
	}
	if hasher != nil {
		return &hashSigner{
			hasher: hasher,
			doSign: doSign,
		}, nil
	} else {
		return &bufferSigner{
			buf:    bytes.NewBuffer(nil),
			doSign: doSign,
		}, nil
	}
}

func (k ed25519VerKey) NewVerifier(options interface{}) (Verifier, error) {
	hasher, err := GetSigningHasher(options)
	if err != nil {
		return nil, err
	}
	doVerify := func(data, sign []byte) error {
		if !ed25519.Verify(ed25519.PublicKey(k[:]), data, sign) {
			return uciph.ErrSignInvalid
		}
		return nil
	}
	if hasher != nil {
		return &hashVerifier{
			hasher:   hasher,
			doVerify: doVerify,
		}, nil
	} else {
		return &bufferVerifier{
			buf:      bytes.NewBuffer(nil),
			doVerify: doVerify,
		}, nil
	}
}
