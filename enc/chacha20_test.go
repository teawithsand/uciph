package enc_test

import (
	"testing"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/enc"
)

func TestChaCha20ED(t *testing.T) {
	var encOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	var decOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	fac := func() (enc.Encryptor, enc.Decryptor) {
		rawKey, err := enc.ChaCha20Poly1305Keygen(nil, nil)
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
	DoTestED(t, fac, TestEDConfig{
		IsAEAD: true,
	})

	// swap nonce mode and run again
	encOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	decOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	DoTestED(t, fac, TestEDConfig{
		IsAEAD: true,
	})
}

func TestXChaCha20ED(t *testing.T) {
	var encOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	var decOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	fac := func() (enc.Encryptor, enc.Decryptor) {
		rawKey, err := enc.ChaCha20Poly1305Keygen(nil, nil)
		if err != nil {
			t.Error(err)
		}
		ek, err := enc.ParseXChaCha20Poly1305EncKey(rawKey)
		if err != nil {
			t.Error(err)
		}
		dk, err := enc.ParseXChaCha20Poly1305DecKey(rawKey)
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
	DoTestED(t, fac, TestEDConfig{
		IsAEAD: true,
	})

	// swap nonce mode and run again
	encOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	decOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	DoTestED(t, fac, TestEDConfig{
		IsAEAD: true,
	})
}

func BenchmarkChaCha20Poly1305ED(b *testing.B) {
	var encOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	var decOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
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

	encOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	decOpts = nmopts{
		nm: enc.NonceModeCounter,
	}

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

func BenchmarkXChaCha20Poly1305ED(b *testing.B) {
	var encOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	var decOpts interface{} = nmopts{
		nm: enc.NonceModeRandom,
	}
	fac := func() (enc.Encryptor, enc.Decryptor) {
		rawKey, err := enc.XChaCha20Poly1305Keygen(nil, nil)
		if err != nil {
			b.Error(err)
		}
		ek, err := enc.ParseXChaCha20Poly1305EncKey(rawKey)
		if err != nil {
			b.Error(err)
		}
		dk, err := enc.ParseXChaCha20Poly1305DecKey(rawKey)
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

	encOpts = nmopts{
		nm: enc.NonceModeCounter,
	}
	decOpts = nmopts{
		nm: enc.NonceModeCounter,
	}

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
