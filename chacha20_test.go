package uciph_test

import (
	"testing"

	"github.com/teawithsand/uciph"
)

type nmopts struct {
	nm uciph.NonceMode
}

func (o nmopts) NonceMode() uciph.NonceMode {
	return o.nm
}

func TestChaCha20EncryptAndDecrypt(t *testing.T) {
	var encOpts interface{} = nmopts{
		nm: uciph.NonceModeRandom,
	}
	var decOpts interface{} = nmopts{
		nm: uciph.NonceModeRandom,
	}
	fac := func() (uciph.Encryptor, uciph.Decryptor) {
		rawKey, err := uciph.ChaCha20Poly1305Keygen.GenSymmKey(nil)
		if err != nil {
			t.Error(err)
		}
		ek, err := uciph.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
		if err != nil {
			t.Error(err)
		}
		dk, err := uciph.ChaCha20Poly1305KeyParser.ParseDecKey(rawKey)
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
	DoTestEncryptorDecryptor(fac, t)

	// swap nonce mode and run again
	encOpts = nmopts{
		nm: uciph.NonceModeCounter,
	}
	decOpts = nmopts{
		nm: uciph.NonceModeCounter,
	}
	DoTestEncryptorDecryptor(fac, t)
}

func BenchmarkChaCha20(b *testing.B) {
	b.Run("encrypt random nonces with default RNG", func(b *testing.B) {
		benchmarkEncryptor(b, func() uciph.Encryptor {
			rawKey, err := uciph.ChaCha20Poly1305Keygen.GenSymmKey(nil)
			if err != nil {
				b.Error(err)
			}
			ek, err := uciph.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
			if err != nil {
				b.Error(err)
			}
			enc, err := ek.NewEncryptor(nmopts{
				nm: uciph.NonceModeRandom,
			})
			if err != nil {
				b.Error(err)
			}
			return enc
		})
	})

	b.Run("encrypt nonce counter", func(b *testing.B) {
		benchmarkEncryptor(b, func() uciph.Encryptor {
			rawKey, err := uciph.ChaCha20Poly1305Keygen.GenSymmKey(nil)
			if err != nil {
				b.Error(err)
			}
			ek, err := uciph.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
			if err != nil {
				b.Error(err)
			}
			enc, err := ek.NewEncryptor(nmopts{
				nm: uciph.NonceModeCounter,
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
			benchmarkDecryptor(b, func() uciph.Encryptor {
				rawKey, err := uciph.ChaCha20Poly1305Keygen.GenSymmKey(nil)
				if err != nil {
					b.Error(err)
				}
				ek, err := uciph.ChaCha20Poly1305KeyParser.ParseEncKey(rawKey)
				if err != nil {
					b.Error(err)
				}
				enc, err := ek.NewEncryptor(nmopts{
					nm: uciph.NonceModeRandom,
				})
				if err != nil {
					b.Error(err)
				}
				return enc
			})
		})
	*/
}
