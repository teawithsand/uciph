package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
)

type aesKey struct {
	buf [32]byte
	sz  int
}

type aesKeyParser struct {
	Size int
}

func checkSize(sz int) (err error) {
	if sz <= 0 || (sz != 128/8 && sz != 192/8 && sz != 256/8) {
		return uciph.ErrInvalidKeySize
	}
	return
}

// AESGCMKeyGen generates ecnryption key for AES GCM with specified size.
func AESGCMKeyGen(size int) (SymEncKeygen, error) {
	err := checkSize(size)
	if err != nil {
		return nil, err
	}
	return SymEncKeygenFunc(func(options interface{}, appendTo []byte) (res []byte, err error) {
		var arr [32]byte
		rng := rand.GetRNG(options)
		_, err = io.ReadFull(rng, arr[:size])
		if err != nil {
			return appendTo, err
		}
		res = append(appendTo, arr[:size]...)
		return
	}), nil
}

// AESGCMKeyParser creates new parser which parses AES GCM keys.
// AES key size may be 128, 192 and 256 bits.
func AESGCMKeyParser(size int) (SymKeyParser, error) {
	err := checkSize(size)
	if err != nil {
		return nil, err
	}
	return aesKeyParser{
		Size: size,
	}, nil
}

func (p aesKeyParser) ParseSymKey(data []byte) (SymKey, error) {
	// if config is set
	// or data length is invalid by definition
	if p.Size > 0 && len(data) != p.Size {
		return nil, uciph.ErrKeyInvalid
	} else if err := checkSize(len(data)); p.Size != 0 && err != nil {
		return nil, uciph.ErrKeyInvalid
	}
	// copy key in case data gets modified
	k := aesKey{}
	copy(k.buf[:p.Size], data[:p.Size])
	k.sz = p.Size
	return k, nil
}

func (p aesKeyParser) ParseEncKey(data []byte) (EncKey, error) {
	return p.ParseSymKey(data)
}

func (p aesKeyParser) ParseDecKey(data []byte) (DecKey, error) {
	return p.ParseSymKey(data)
}

func (k aesKey) getBuf() []byte {
	return k.buf[:k.sz]
}

func (k aesKey) NewEncryptor(options interface{}) (Encryptor, error) {
	block, err := aes.NewCipher(k.getBuf())
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
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

func (k aesKey) NewDecryptor(options interface{}) (Decryptor, error) {
	block, err := aes.NewCipher(k.getBuf())
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
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
