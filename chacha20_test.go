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

	rep(assert([][]byte{}))
	rep(assert([][]byte{
		[]byte{0x01},
	}))
	rep(assert([][]byte{
		[]byte{0x01},
		[]byte{0x02},
	}))

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

func TestChaCha20EncryptAndDecrypt(t *testing.T) {
	var encOpts interface{}
	var decOpts interface{}
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
	for i := 0; i < 10; i++ {
		DoTestEncryptorDecryptor(fac, t)
	}
}
