package enc_test

import (
	"testing"

	"github.com/teawithsand/uciph/enc"
)

type nmopts struct {
	nm enc.NonceMode
}

func (o nmopts) NonceMode() enc.NonceMode {
	return o.nm
}

func TestChaCha20EncryptAndDecrypt(t *testing.T) {
	var encOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	var decOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	fac := func() (enc.Encryptor, enc.Decryptor) {
		rawKey, err := enc.ChaCha20Poly1305Keygen().GenSymmKey(nil, nil)
		if err != nil {
			t.Error(err)
		}
		ek, err := enc.ChaCha20Poly1305KeyParser().ParseEncKey(rawKey)
		if err != nil {
			t.Error(err)
		}
		dk, err := enc.ChaCha20Poly1305KeyParser().ParseDecKey(rawKey)
		if err != nil {
			t.Error(err)
		}
		enc, err := ek.NewEncryptor(encOpts)
		if err != nil {
			t.Error(err)
		}
		dec, err := dk.NewDecryptor(decOpts)
		if err != nil {
			t.Error(err)
		}
		return enc, dec
	}
	DoTestEncryptorDecryptor(t.Error, fac, testData{IsAEAD: true})

	// swap nonce mode and run again
	encOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	decOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	DoTestEncryptorDecryptor(t.Error, fac, testData{IsAEAD: true})
}

/*

func BenchmarkChaCha20(b *testing.B) {
	b.Run("encrypt random nonces with default RNG", func(b *testing.B) {
		benchmarkEncryptor(b, func() enc.Encryptor {
			rawKey, err := enc.ChaCha20Poly1305Keygen.GenSymmKey(nil)
			if err != nil {
				b.Error(err)
			}
			ek, err := enc.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
			if err != nil {
				b.Error(err)
			}
			enc, err := ek.NewEncryptor(nmopts{
				nm: enc.NonceModeRandom,
			})
			if err != nil {
				b.Error(err)
			}
			return enc
		})
	})

	b.Run("encrypt nonce counter", func(b *testing.B) {
		benchmarkEncryptor(b, func() enc.Encryptor {
			rawKey, err := enc.ChaCha20Poly1305Keygen.GenSymmKey(nil)
			if err != nil {
				b.Error(err)
			}
			ek, err := enc.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
			if err != nil {
				b.Error(err)
			}
			enc, err := ek.NewEncryptor(nmopts{
				nm: enc.NonceModeCounter,
			})
			if err != nil {
				b.Error(err)
			}
			return enc
		})
	})
	// TODO(teawithsand): add decryptor benchmarks
	/*
		b.Run("decrypt random nonces", func(b *testing.B) {
			benchmarkDecryptor(b, func() enc.Encryptor {
				rawKey, err := enc.ChaCha20Poly1305Keygen.GenSymmKey(nil)
				if err != nil {
					b.Error(err)
				}
				ek, err := enc.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
				if err != nil {
					b.Error(err)
				}
				enc, err := ek.NewEncryptor(nmopts{
					nm: enc.NonceModeRandom,
				})
				if err != nil {
					b.Error(err)
				}
				return enc
			})
		})
	* /
}
*/
