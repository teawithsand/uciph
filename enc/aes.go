package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"golang.org/x/crypto/chacha20poly1305"
)

// AESKeySize denotes AES key size(in bits), which is accepted by this library.
type AESKeySize int

const (
	// AES128 with 128 bit key. Should be default choice.
	AES128 AESKeySize = 128
	// AES192 with 192 bit key.
	AES192 AESKeySize = 192
	// AES256 with 256 bit key. Used to secure data against quantumm computers.
	AES256 AESKeySize = 256
)

// Check checks if AES key is valid or not.
func (s AESKeySize) Check() (err error) {
	size := int(s)
	if size != 128 && size != 192 && size != 256 {
		return uciph.ErrInvalidKeySize
	}

	return
}

// AESKeygen generates AES key.
func AESKeygen(options interface{}, size AESKeySize, dst []byte) (res []byte, err error) {
	err = size.Check()
	if err != nil {
		return
	}

	rng := rand.GetRNG(options)
	var key [chacha20poly1305.KeySize]byte
	_, err = io.ReadFull(rng, key[:])
	if err != nil {
		return dst, err
	}
	res = append(dst, key[:]...)
	return
}

// NewAESKeygen creates new keygen for AES with specified key size.
func NewAESKeygen(size AESKeySize) (kg SymmKeygen, err error) {
	err = size.Check()
	if err != nil {
		return
	}

	kg = func(options interface{}, dst []byte) (res []byte, err error) {
		return AESKeygen(options, size, dst)
	}
	return
}

// TODO(teawithsand): perser factories accepting key size and creating parser

// ParseAESEncKey parses AES encryption key with specified size for encryptors.
func ParseAESEncKey(key []byte, size AESKeySize) (k EncKey, err error) {
	err = size.Check()
	if err != nil {
		return
	}

	if len(key) != int(size) {
		err = uciph.ErrInvalidKeySize
		return
	}

	var cpKey [chacha20poly1305.KeySize]byte
	copy(cpKey[:], key[:])

	k = func(options interface{}) (Encryptor, error) {
		block, err := aes.NewCipher(cpKey[:])
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
	return
}

// ParseAESDecKey parses AES encryption key with specified size for decryptors.
func ParseAESDecKey(key []byte, size AESKeySize) (k DecKey, err error) {
	err = size.Check()
	if err != nil {
		return
	}

	if len(key) != int(size) {
		err = uciph.ErrInvalidKeySize
		return
	}

	var cpKey [chacha20poly1305.KeySize]byte
	copy(cpKey[:], key[:])

	k = func(options interface{}) (Decryptor, error) {
		block, err := aes.NewCipher(cpKey[:])
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
	return
}
