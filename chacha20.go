package uciph

import (
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Keygen generates new ChaCha20Poly1305 key.
// This cipher is authenticated and does not require additional MAC.
var ChaCha20Poly1305Keygen SymmEncKeygen = SymmEncKeygenFunc(func(options KeygenOptions) (data []byte, err error) {
	rng := GetRNG(options)
	var key [chacha20poly1305.KeySize]byte
	_, err = io.ReadFull(rng, key[:])
	if err != nil {
		return
	}
	return key[:], nil
})

var ChaCha20Poly1305KeyParser SymmKeyParser = chacha20KeyParser{}

type chacha20KeyParser struct{}

func (chacha20KeyParser) ParseSymmKey(data []byte) (ParsedSymmKey, error) {
	if len(data) != chacha20poly1305.KeySize {
		return nil, ErrKeyInvalid
	}
	return chacha20Key(data), nil
}

func (p chacha20KeyParser) ParseEncKey(data []byte) (ParsedEncKey, error) {
	return p.ParseSymmKey(data)
}

func (p chacha20KeyParser) ParseDecKey(data []byte) (ParsedDecKey, error) {
	return p.ParseSymmKey(data)
}

type chacha20Key []byte

func (k chacha20Key) NewEncryptor(options EncKeyOptions) (Encryptor, error) {
	// TODO(teawithsand): add some options here for nonce and other stuff
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	return NewRNGAEADEncryptor(aead, options), nil
}

func (k chacha20Key) NewDecryptor(options DecKeyOptions) (Decryptor, error) {
	// TODO(teawithsand): add some options here for nonce and other stuff
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	return NewRNGAEADDecryptor(aead, options), nil
}
