package uciph_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/teawithsand/uciph"
)

func DoTestEncryptorDecryptor(
	fac func() (uciph.Encryptor, uciph.Decryptor),
	t *testing.T,
) {
	assert := func(data [][]byte) (err error) {
		enc, dec := fac()
		res := make([][]byte, len(data))
		for i, plain := range data {
			encC, err := enc.Encrypt(plain, nil)
			if err != nil {
				return err
			}
			res[i] = encC
		}

		for i, encC := range res {
			plain, err := dec.Decrypt(encC, nil)
			if err != nil {
				return err
			}
			if bytes.Compare(plain, data[i]) != 0 {
				return errors.New("Texts not equal")
			}
		}

		return
	}
	rep := func(err error) {
		if err != nil {
			t.Error(err)
		}
	}
	rng := uciph.GetRNG(nil)

	for i := 0; i < 10; i++ {
		rep(assert([][]byte{}))
		rep(assert([][]byte{
			[]byte{0x01},
		}))
		rep(assert([][]byte{
			[]byte{0x01},
			[]byte{0x02},
		}))

		{
			td := make([][]byte, 0)
			for i := 0; i < 10; i++ {
				b := make([]byte, 4096)
				_, err := io.ReadFull(rng, b[:])
				if err != nil {
					t.Error(err)
				}
				td = append(td, b)
			}
			rep(assert(td))
		}

		{
			td := make([][]byte, 0)
			for i := 0; i < 10; i++ {
				b := make([]byte, 5*i*i*i+3*i*i+20*i+3)
				_, err := io.ReadFull(rng, b[:])
				if err != nil {
					t.Error(err)
				}
				td = append(td, b)
			}
			rep(assert(td))
		}
	}
}
