package enc_test

import (
	"fmt"
	"testing"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/copts"
	"github.com/teawithsand/uciph/ctest"
	"github.com/teawithsand/uciph/enc"
)

func TestAESED(t *testing.T) {
	for _, ks := range []enc.AESKeySize{
		enc.AES128,
		enc.AES192,
		enc.AES256,
	} {
		ks := ks
		var encOpts interface{} = copts.Options{}.WithNonceMode(enc.NonceModeRandom)
		decOpts := encOpts
		fac := func() (enc.Encryptor, enc.Decryptor) {
			rawKey, err := enc.AESKeygen(nil, ks, nil)
			if err != nil {
				t.Error(err)
			}
			ek, err := enc.ParseChaCha20Poly1305EncKey(rawKey)
			if err != nil {
				t.Error(err)
			}
			dk, err := enc.ParseChaCha20Poly1305DecKey(rawKey)
			if err != nil {
				t.Error(err)
			}
			enc, err := ek(encOpts)
			if err != nil {
				t.Error(err)
			}
			dec, err := dk(decOpts)
			if err != nil {
				t.Error(err)
			}
			return enc, dec
		}
		t.Run(fmt.Sprintf("RandomNonce_AES%d", int(ks)), func(t *testing.T) {
			ctest.DoTestED(t, fac, ctest.TestEDConfig{
				IsAEAD: true,
			})
		})
		t.Run(fmt.Sprintf("NonceCounter_AES%d", int(ks)), func(t *testing.T) {
			ctest.DoTestED(t, fac, ctest.TestEDConfig{
				IsAEAD: true,
			})

			// swap nonce mode and run again
			encOpts = copts.Options{}.WithNonceMode(enc.NonceModeCounter)
			decOpts = encOpts
			ctest.DoTestED(t, fac, ctest.TestEDConfig{
				IsAEAD: true,
			})
		})

	}
}

func BenchmarkAESED(b *testing.B) {
	var encOpts interface{} = copts.Options{}.WithNonceMode(enc.NonceModeRandom)
	var decOpts interface{} = copts.Options{}.WithNonceMode(enc.NonceModeRandom)
	fac := func() (enc.Encryptor, enc.Decryptor) {
		rawKey, err := enc.XChaCha20Poly1305Keygen(nil, nil)
		if err != nil {
			b.Error(err)
		}
		ek, err := enc.ParseChaCha20Poly1305EncKey(rawKey)
		if err != nil {
			b.Error(err)
		}
		dk, err := enc.ParseChaCha20Poly1305DecKey(rawKey)
		if err != nil {
			b.Error(err)
		}
		enc, err := ek(encOpts)
		if err != nil {
			b.Error(err)
		}
		dec, err := dk(decOpts)
		if err != nil {
			b.Error(err)
		}
		return enc, dec
	}

	// swap nonce mode and run again
	b.Run("RandomNonce", func(b *testing.B) {
		cbe := cbench.EDBenchEngine{
			Fac: fac,
			Config: cbench.EDBenchConfig{
				Runs: cbench.GenereateDefaultEDRuns(true),
			},
		}
		cbe.RunEDBenchmark(b)
	})

	encOpts = copts.Options{}.WithNonceMode(enc.NonceModeCounter)
	decOpts = copts.Options{}.WithNonceMode(enc.NonceModeCounter)

	b.Run("CounterNonce", func(b *testing.B) {
		cbe := cbench.EDBenchEngine{
			Fac: fac,
			Config: cbench.EDBenchConfig{
				Runs: cbench.GenereateDefaultEDRuns(false),
			},
		}
		cbe.RunEDBenchmark(b)
	})
}
