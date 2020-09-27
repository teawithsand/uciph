package enc_test

import (
	"io"
	"testing"

	"github.com/teawithsand/uciph/copts"
	"github.com/teawithsand/uciph/ctest"
	"github.com/teawithsand/uciph/enc"
)

func TestStreamED(t *testing.T) {
	t.Run("BlanKED", func(t *testing.T) {
		d := enc.BlankDecryptor()
		e := enc.BlankEncryptor()

		ctest.DoTestStreamED(t, func(w io.Writer) enc.StreamEncryptor {
			return enc.NewDefaultStreamEncryptor(e, w)
		}, func(r io.Reader) enc.StreamDecryptor {
			return enc.NewDefaultStreamDecryptor(d, r)
		})
	})
	t.Run("ChaCha20ED_RandomNonce", func(t *testing.T) {
		var encOpts interface{} = copts.Options{}.WithNonceMode(enc.NonceModeRandom)
		decOpts := encOpts

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
		e, err := ek(encOpts)
		if err != nil {
			t.Error(err)
		}
		d, err := dk(decOpts)
		if err != nil {
			t.Error(err)
		}

		ctest.DoTestStreamED(t, func(w io.Writer) enc.StreamEncryptor {
			return enc.NewDefaultStreamEncryptor(e, w)
		}, func(r io.Reader) enc.StreamDecryptor {
			return enc.NewDefaultStreamDecryptor(d, r)
		})
	})

	t.Run("ChaCha20ED_CounterNonce", func(t *testing.T) {
		var encOpts interface{} = copts.Options{}.WithNonceMode(enc.NonceModeCounter)
		decOpts := encOpts

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
		e, err := ek(encOpts)
		if err != nil {
			t.Error(err)
		}
		d, err := dk(decOpts)
		if err != nil {
			t.Error(err)
		}

		ctest.DoTestStreamED(t, func(w io.Writer) enc.StreamEncryptor {
			return enc.NewDefaultStreamEncryptor(e, w)
		}, func(r io.Reader) enc.StreamDecryptor {
			return enc.NewDefaultStreamDecryptor(d, r)
		})
	})
}

// TODO(teawithsand): benchmarks for stream encryptor/decryptor
