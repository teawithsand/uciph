package sig_test

import (
	"crypto"
	"testing"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/teawithsand/uciph/ctest"
	"github.com/teawithsand/uciph/sig"
)

func TestCryptoSHA256Hasher(t *testing.T) {
	ctest.DoTestHasher(t, func() sig.Hasher {
		hf, err := sig.NewCryptoHasherFac(crypto.SHA256)
		if err != nil {
			t.Error(err)
		}
		h, err := hf(nil)
		if err != nil {
			t.Error(err)
		}
		return h
	})
}

func TestCryptoSHA512Hasher(t *testing.T) {
	ctest.DoTestHasher(t, func() sig.Hasher {
		hf, err := sig.NewCryptoHasherFac(crypto.SHA512)
		if err != nil {
			t.Error(err)
		}
		h, err := hf(nil)
		if err != nil {
			t.Error(err)
		}
		return h
	})
}

func TestCryptoSHA256HMACHasher(t *testing.T) {
	hkp, err := sig.NewHMAC(crypto.SHA256, []byte{
		1, 2, 3, 4,
	})
	if err != nil {
		t.Error(err)
	}

	ctest.DoTestHasher(t, func() sig.Hasher {
		h, err := hkp(nil)
		if err != nil {
			t.Error(err)
		}
		return h
	})
}

// TODO(teawithsand): benchmarking with new benchmark engine

/*
func BenchmarkHashCryptoSHA256(b *testing.B) {
	bechmarkHash(b, func() sig.Hasher {
		hf, _ := sig.NewCryptoHasherFactory(crypto.SHA256)
		h, err := hf.NewHasher(nil)
		if err != nil {
			b.Error(err)
		}
		return h
	})
}

func BenchmarkHMACCryptoSHA256(b *testing.B) {
	hkp, err := sig.NewHMACKeyParser(crypto.SHA256)
	if err != nil {
		b.Error(err)
	}
	kh, err := hkp.ParseHMACKey([]byte{
		1, 2, 3, 4,
	})
	if err != nil {
		b.Error(err)
	}

	bechmarkHash(b, func() sig.Hasher {
		h, err := kh.NewHasher(nil)
		if err != nil {
			b.Error(err)
		}
		return h
	})
}

func BenchmarkHashCryptoSHA512(b *testing.B) {
	bechmarkHash(b, func() sig.Hasher {
		hf, _ := sig.NewCryptoHasherFactory(crypto.SHA256)
		h, err := hf.NewHasher(nil)
		if err != nil {
			b.Error(err)
		}
		return h
	})
}
*/
