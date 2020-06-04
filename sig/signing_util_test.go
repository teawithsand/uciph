package sig_test

import (
	"errors"
	"io"
	"testing"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"github.com/teawithsand/uciph/sig"
)

func DoTestSignerVerifier(
	fac func() (sig.Signer, sig.Verifier),
	// used because buffer signers are not able to handle big data streams
	doBigTest bool,
	t *testing.T,
) {
	var tests []func([]byte) error
	// 1. Test correct sign is always correct
	tests = append(tests, func(data []byte) (err error) {
		signer, verifier := fac()

		_, err = signer.Write(data)
		if err != nil {
			return
		}

		sign, err := signer.Sign(nil)
		if err != nil {
			return
		}

		_, err = verifier.Write(data)
		if err != nil {
			return
		}

		err = verifier.Verify(sign)
		if err != nil {
			return
		}

		return
	})

	// 2. Test sign is correct when writes are splitted
	tests = append(tests, func(data []byte) (err error) {
		signer, verifier := fac()

		for _, b := range data {
			_, err = signer.Write([]byte{b})
			if err != nil {
				return
			}
		}

		sign, err := signer.Sign(nil)
		if err != nil {
			return
		}

		for _, b := range data {
			_, err = verifier.Write([]byte{b})
			if err != nil {
				return
			}
		}

		err = verifier.Verify(sign)
		if err != nil {
			return
		}

		return
	})

	// 3. Test sign is correct when verifier writes are splitted
	tests = append(tests, func(data []byte) (err error) {
		signer, verifier := fac()

		_, err = signer.Write(data)
		if err != nil {
			return
		}

		sign, err := signer.Sign(nil)
		if err != nil {
			return
		}

		for _, b := range data {
			_, err = verifier.Write([]byte{b})
			if err != nil {
				return
			}
		}

		err = verifier.Verify(sign)
		if err != nil {
			return
		}

		return
	})

	// 4. Test sign is correct when signer writes are splitted
	tests = append(tests, func(data []byte) (err error) {
		signer, verifier := fac()

		for _, b := range data {
			_, err = signer.Write([]byte{b})
			if err != nil {
				return
			}
		}

		sign, err := signer.Sign(nil)
		if err != nil {
			return
		}

		_, err = verifier.Write(data)
		if err != nil {
			return
		}

		err = verifier.Verify(sign)
		if err != nil {
			return
		}

		return
	})

	// 5. Test invalid sign is invalid
	tests = append(tests, func(data []byte) (err error) {
		signer, verifier := fac()

		_, err = signer.Write(data)
		if err != nil {
			return
		}

		sign, err := signer.Sign(nil)
		if err != nil {
			return
		}

		_, err = verifier.Write(data)
		if err != nil {
			return
		}

		rng := rand.GetRNG(nil)
		_, err = io.ReadFull(rng, sign[:])
		if err != nil {
			return
		}

		err = verifier.Verify(sign)
		if err != uciph.ErrSignInvalid {
			if err == nil {
				err = errors.New("Expected verifying error here!")
			}
			return
		}

		err = nil

		return
	})

	datasets := make([][]byte, 0)
	datasets = append(datasets, []byte{})
	datasets = append(datasets, []byte{
		1, 2, 3, 4, 5,
	})
	datasets = append(datasets, []byte{
		0xaa, 0xbb, 0xcc, 0xdd,
	})

	for _, ds := range datasets {
		for _, test := range tests {
			err := test(ds)
			if err != nil {
				t.Error(err)
			}
		}
	}
}
