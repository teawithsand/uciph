package uciph

import (
	"crypto/cipher"
	"io"
)

// NewCtrAEADEncryptor wraps any AEAD and uses it to encrypt chunks.
// It uses nonce coutner to manage nonces.
func NewCtrAEADEncryptor(aead cipher.AEAD, nc NonceCounter) Encryptor {
	if aead.NonceSize() != nc.Len() {
		panic("uciph: Nonce length mismatch between cipher.AEAD and NonceCounter")
	}
	return EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		defer func() {
			err = nc.Increment() // is error set in defer? it should be AFAIK TODO(teawithsand): test it
		}()
		res = aead.Seal(appendTo, nc[:], in, nil)
		return
	})
}

// NewCtrAEADDecryptor wraps any AEAD and uses it to decrypt chunks.
// It uses nonce coutner to manage nonces.
func NewCtrAEADDecryptor(aead cipher.AEAD, nc NonceCounter) Decryptor {
	if aead.NonceSize() != nc.Len() {
		panic("uciph: Nonce length mismatch between cipher.AEAD and NonceCounter")
	}
	return DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		defer func() {
			if err == nil {
				// increment only if succeed? Anyhow decryptor should not be reused after failure.
				err = nc.Increment()
			}
		}()
		res, err = aead.Open(appendTo, nc[:], in, nil)
		return
	})
}

// NewRNGAEADEncryptor creates new encryptor, which uses RNG from options to generate
// nonces.
// Note: It has no limit dependent on nonce length, which may be unsafe sometimes.
// For instance 12 byte random nonce should not be used more than 2**32 times!
func NewRNGAEADEncryptor(aead cipher.AEAD, options interface{}) Encryptor {
	nc := make([]byte, aead.NonceSize())
	rng := GetRNG(options)

	return EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		_, err = io.ReadFull(rng, nc[:])
		if err != nil {
			return
		}
		// TODO(teaiwithsand): debug in place calls

		// note: nonce size is known
		// so there is no need to write it
		appendTo = append(appendTo, nc[:]...)
		res = aead.Seal(appendTo[:], nc[:], in, nil)
		copy(appendTo, nc[:]) // TOOD(tewithsand): make sure this hack works with all ciphers with tests
		return
	})
}

// NewRNGAEADDecryptor creates new decryptor, which is able to decrypt data encrypted using NewRngAEADEncryptor.
func NewRNGAEADDecryptor(aead cipher.AEAD, options interface{}) Decryptor {
	nsz := aead.NonceSize()
	return DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		if len(in) < nsz {
			err = ErrNonceInvalid
			return
		}
		// TODO(teaiwithsand): debug in place calls
		res, err = aead.Open(appendTo, in[:nsz], in[nsz:], nil)
		return
	})
}
