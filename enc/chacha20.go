package enc

import (
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"golang.org/x/crypto/chacha20poly1305"
)

var chaCha20Poly1305Keygen SymEncKeygen = SymEncKeygenFunc(func(options interface{}, appendTo []byte) (res []byte, err error) {
	rng := rand.GetRNG(options)
	var key [chacha20poly1305.KeySize]byte
	_, err = io.ReadFull(rng, key[:])
	if err != nil {
		return appendTo, err
	}
	res = append(appendTo, key[:]...)
	return
})

// ChaCha20Poly1305Keygen generates new ChaCha20Poly1305 key.
// This cipher is authenticated and does not require additional MAC.
// Note: it uses 24 bytes nonces.
func ChaCha20Poly1305Keygen() SymEncKeygen {
	return chaCha20Poly1305Keygen
}

var chaCha20Poly1305KeyParser SymKeyParser = chacha20KeyParser{}

// ChaCha20Poly1305KeyParser returns parser for ChaCha20Poly1305 keys.
// It requires 256 bits keys.
// Note: it uses 24 bytes nonces.
func ChaCha20Poly1305KeyParser() SymKeyParser {
	return chaCha20Poly1305KeyParser
}

type chacha20KeyParser struct{}

func (chacha20KeyParser) ParseSymKey(data []byte) (SymKey, error) {
	if len(data) != chacha20poly1305.KeySize {
		return nil, uciph.ErrKeyInvalid
	}
	return chacha20Key(data), nil
}

func (p chacha20KeyParser) ParseEncKey(data []byte) (EncKey, error) {
	return p.ParseSymKey(data)
}

func (p chacha20KeyParser) ParseDecKey(data []byte) (DecKey, error) {
	return p.ParseSymKey(data)
}

type chacha20Key []byte

func (k chacha20Key) NewEncryptor(options interface{}) (Encryptor, error) {
	// TODO(teawithsand): add some options here for nonce and other stuff
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	nm := GetNonceMode(options)
	switch nm {
	case NonceModeCounter:
		return NewCtrAEADEncryptor(aead, options), nil
	/*
		case NonceModeRandom:
			fallthrough
	*/
	default:
		return NewRNGAEADEncryptor(aead, options), nil
	}
}

func (k chacha20Key) NewDecryptor(options interface{}) (Decryptor, error) {
	// TODO(teawithsand): add some options here for nonce and other stuff
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	nm := GetNonceMode(options)
	switch nm {
	case NonceModeCounter:
		return NewCtrAEADDecryptor(aead, options), nil
	/*
		case NonceModeRandom:
			fallthrough
	*/
	default:
		return NewRNGAEADDecryptor(aead, options), nil
	}
}
