package enc_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/rand"
)

func makeTestChunks(r io.Reader, sizes ...int) [][]byte {
	res := make([][]byte, len(sizes))
	for i, sz := range sizes {
		res[i] = make([]byte, sz)
		_, err := io.ReadFull(r, res[i])
		if err != nil {
			panic(err)
		}
	}
	return res
}

type TestEDConfig struct {
	IsAEAD bool
}

func DoTestED(
	t *testing.T,
	fac func() (enc.Encryptor, enc.Decryptor),
	config TestEDConfig,
) {
	assert := func(t *testing.T, err error) {
		if err != nil {
			t.Error(err)
		}
	}

	t.Run("TestEncryptDecryptValid", func(t *testing.T) {
		testPass := func(chunks [][]byte) (err error) {
			e, d := fac()

			res := make([][]byte, len(chunks))
			for i, c := range chunks {
				res[i], err = e.Encrypt(c, nil)
				if err != nil {
					return
				}
			}

			for i, c := range res {
				var data []byte
				data, err = d.Decrypt(c, nil)
				if err != nil {
					return
				}
				if bytes.Compare(data, chunks[i]) != 0 {
					err = errors.New("Input and output differ!")
					return
				}
			}
			return
		}

		run := func(rng io.Reader) {

			// 1. Small single chunk
			for i := 0; i < 32; i++ {
				assert(t, testPass(makeTestChunks(rand.ZeroRNG(), i)))
			}

			// 2. Multiple chunks
			assert(t, testPass(makeTestChunks(rng, 1024)))
			assert(t, testPass(makeTestChunks(rng, 1024, 1024)))
			assert(t, testPass(makeTestChunks(rng, 1024, 1024, 1024)))
			assert(t, testPass(makeTestChunks(rng, 1024, 1024, 1024, 1024)))
		}
		run(rand.ZeroRNG())
		run(rand.DefaultRNG())
	})

	if config.IsAEAD {
		t.Run("TestDecryptFailsOnBadKey", func(t *testing.T) {
			testPass := func(chunk []byte) (err error) {
				e, _ := fac()
				chunk, err = e.Encrypt(chunk, nil)
				if err != nil {
					return
				}

				_, d := fac()
				_, err = d.Decrypt(chunk, nil)
				if err == nil {
					err = errors.New("Error is nil but expected it not to be")
				} else {
					err = nil
				}
				return
			}

			// assert(t, testPass([]byte{1, 2, 3}))

			run := func(rng io.Reader) {
				// 1. Small single chunk
				for i := 0; i < 32; i++ {
					assert(t, testPass(makeTestChunks(rng, i)[0]))
				}
			}
			run(rand.ZeroRNG())
			run(rand.DefaultRNG())

		})
	}

	t.Run("TestDecryptOverlapFull", func(t *testing.T) {
		testPass := func(chunk []byte) (err error) {
			e, d := fac()
			chunk, err = e.Encrypt(chunk, nil)
			if err != nil {
				return
			}

			_, err = d.Decrypt(chunk, chunk[:0])
			if err != nil {
				return
			}

			return
		}

		run := func(rng io.Reader) {
			// 1. Small single chunk
			for i := 0; i < 32; i++ {
				assert(t, testPass(makeTestChunks(rng, i)[0]))
			}
		}

		run(rand.ZeroRNG())
		run(rand.DefaultRNG())
	})

	/*
		// TODO(teawithsand): make this test pass
		t.Run("TestDecryptOverlapPartial", func(t *testing.T) {
			testPass := func(chunk []byte) (err error) {
				e, d := fac()
				chunk, err = e.Encrypt(chunk, nil)
				if err != nil {
					return
				}

				_, err = d.Decrypt(chunk, chunk[:1])
				if errors.Is(err, uciph.ErrInvalidOverlap) {
					err = nil
				} else if err != nil {
					return
				}

				return
			}

			run := func(rng io.Reader) {
				// 1. Small single chunk
				for i := 0; i < 32; i++ {
					assert(t, testPass(makeTestChunks(rng, i)[0]))
				}
			}

			run(rand.ZeroRNG())
			run(rand.DefaultRNG())
		})
	*/
}
