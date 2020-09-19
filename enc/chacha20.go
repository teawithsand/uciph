package enc

import (
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Keygen generates ChaCha20 key.
// Note: it's compatibile with XChaCha20Poly1305Keygen.
func ChaCha20Poly1305Keygen(options interface{}, dst []byte) (res []byte, err error) {
	rng := rand.GetRNG(options)
	var key [chacha20poly1305.KeySize]byte
	_, err = io.ReadFull(rng, key[:])
	if err != nil {
		return dst, err
	}
	res = append(dst, key[:]...)
	return
}

// XChaCha20Poly1305Keygen generates XChaCha20 key.
// Note: it's compatibile with ChaCha20Poly1305Keygen.
func XChaCha20Poly1305Keygen(options interface{}, dst []byte) (res []byte, err error) {
	rng := rand.GetRNG(options)
	var key [chacha20poly1305.KeySize]byte
	_, err = io.ReadFull(rng, key[:])
	if err != nil {
		return dst, err
	}
	res = append(dst, key[:]...)
	return
}

// ParseXChaCha20Poly1305EncKey parses ChaCha20Poly1305 key from bytes for encryption.
func ParseXChaCha20Poly1305EncKey(key []byte) (EncKey, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, uciph.ErrKeyInvalid
	}

	var cpKey [chacha20poly1305.KeySize]byte
	copy(cpKey[:], key[:])

	return func(options interface{}) (Encryptor, error) {
		// TODO(teawithsand): add some options here for nonce and other stuff
		aead, err := chacha20poly1305.NewX(cpKey[:])
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
	}, nil
}

// ParseXChaCha20Poly1305DecKey parses ChaCha20Poly1305 key from bytes for decryption.
func ParseXChaCha20Poly1305DecKey(key []byte) (DecKey, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, uciph.ErrKeyInvalid
	}

	var cpKey [chacha20poly1305.KeySize]byte
	copy(cpKey[:], key[:])

	return func(options interface{}) (Decryptor, error) {
		// TODO(teawithsand): add some options here for nonce and other stuff
		aead, err := chacha20poly1305.NewX(cpKey[:])
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
	}, nil
}

// ParseChaCha20Poly1305EncKey parses ChaCha20Poly1305 key from bytes for encryption.
func ParseChaCha20Poly1305EncKey(key []byte) (EncKey, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, uciph.ErrKeyInvalid
	}

	var cpKey [chacha20poly1305.KeySize]byte
	copy(cpKey[:], key[:])

	return func(options interface{}) (Encryptor, error) {
		// TODO(teawithsand): add some options here for nonce and other stuff
		aead, err := chacha20poly1305.New(cpKey[:])
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
	}, nil
}

// ParseChaCha20Poly1305DecKey parses ChaCha20Poly1305 key from bytes for decryption.
func ParseChaCha20Poly1305DecKey(key []byte) (DecKey, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, uciph.ErrKeyInvalid
	}

	var cpKey [chacha20poly1305.KeySize]byte
	copy(cpKey[:], key[:])

	return func(options interface{}) (Decryptor, error) {
		// TODO(teawithsand): add some options here for nonce and other stuff
		aead, err := chacha20poly1305.New(cpKey[:])
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
	}, nil
}

// TODO(teawithsand): add support for streamming non-AEAD parses
