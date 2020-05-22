package uciph_test

import (
	"bytes"
	"crypto"
	"errors"
	"testing"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/teawithsand/uciph"
)

func DoTestHasher(
	t *testing.T,
	hashf func() uciph.Hasher,
) {

	assert := func(err error) {
		if err != nil {
			t.Error(err)
		}
	}

	var btests []func([]byte) error

	// 1. For same data result is same
	{
		test := func(c []byte) (err error) {
			h1 := hashf()
			h2 := hashf()

			_, err = h1.Write(c)
			if err != nil {
				return
			}
			_, err = h2.Write(c)
			if err != nil {
				return
			}
			s1, err := h1.Sum(nil)
			if err != nil {
				return
			}
			s2, err := h2.Sum(nil)
			if err != nil {
				return
			}

			if bytes.Compare(s1, s2) != 0 {
				err = errors.New("Slices are not equal!")
			}

			return
		}
		btests = append(btests, test)
	}

	// 2. For same data result is same when written byte-by-byte
	{
		test := func(c []byte) (err error) {
			h1 := hashf()
			h2 := hashf()

			_, err = h1.Write(c)
			if err != nil {
				return
			}
			for _, b := range c {
				_, err = h2.Write([]byte{b})
				if err != nil {
					return
				}
			}
			s1, err := h1.Sum(nil)
			if err != nil {
				return
			}
			s2, err := h2.Sum(nil)
			if err != nil {
				return
			}

			if bytes.Compare(s1, s2) != 0 {
				err = errors.New("Slices are not equal!")
			}

			return
		}
		btests = append(btests, test)
	}

	for _, test := range btests {
		assert(test([]byte{}))
		assert(test([]byte{1, 2, 3, 4}))
		assert(test([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}))
		assert(test(make([]byte, 1024*4)))
		assert(test(make([]byte, 1024*16)))
	}

}

func TestCryptoSHA256Hasher(t *testing.T) {
	DoTestHasher(t, func() uciph.Hasher {
		hf, err := uciph.NewCryptoHasherFactory(crypto.SHA256)
		if err != nil {
			t.Error(err)
		}
		h := hf.NewHasher(nil)
		return h
	})
}

func TestCryptoSHA512Hasher(t *testing.T) {
	DoTestHasher(t, func() uciph.Hasher {
		hf, err := uciph.NewCryptoHasherFactory(crypto.SHA512)
		if err != nil {
			t.Error(err)
		}
		h := hf.NewHasher(nil)
		return h
	})
}

func BenchmarkHashCryptoSHA256(b *testing.B) {
	bechmarkHash(b, func() uciph.Hasher {
		hf, _ := uciph.NewCryptoHasherFactory(crypto.SHA256)
		h := hf.NewHasher(nil)
		return h
	})
}

func BenchmarkHashCryptoSHA512(b *testing.B) {
	bechmarkHash(b, func() uciph.Hasher {
		hf, _ := uciph.NewCryptoHasherFactory(crypto.SHA256)
		h := hf.NewHasher(nil)
		return h
	})
}
