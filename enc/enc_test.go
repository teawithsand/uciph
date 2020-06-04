package enc_test

import (
	"bytes"
	"errors"
	"io"

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

type testData struct {
	IsAEAD bool
}

// TODO(teawithsand): test for overlapping slices(since it may crash now)
func DoTestEncryptorDecryptor(
	rep func(args ...interface{}), // by default t.Error or b.Error
	fac func() (enc.Encryptor, enc.Decryptor),
	td testData,
) {
	assert := func(err error) {
		if err != nil {
			rep(err)
		}
	}

	// 1. Enc/dec test
	{
		test := func(chunks [][]byte) (err error) {
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
				assert(test(makeTestChunks(rand.ZeroRNG(), i)))
			}

			// 2. Multiple chunks
			assert(test(makeTestChunks(rng, 1024)))
			assert(test(makeTestChunks(rng, 1024, 1024)))
			assert(test(makeTestChunks(rng, 1024, 1024, 1024)))
			assert(test(makeTestChunks(rng, 1024, 1024, 1024, 1024)))
		}
		run(rand.ZeroRNG())
		run(rand.DefaultRNG())
	}

	// 2. Expect failure - bad key test
	if td.IsAEAD {
		test := func(chunk []byte) (err error) {
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

		run := func(rng io.Reader) {

			// 1. Small single chunk
			for i := 0; i < 32; i++ {
				assert(test(makeTestChunks(rand.ZeroRNG(), i)[0]))
			}
		}
		run(rand.ZeroRNG())
		run(rand.DefaultRNG())
	}
	// 3. Decrypt partial overlapping test
	test := func(chunk []byte) (err error) {
		// 1. Valid overlap
		{
			e, d := fac()
			chunk, err = e.Encrypt(chunk, nil)
			if err != nil {
				return
			}

			_, err = d.Decrypt(chunk, chunk[:0])
			if err != nil {
				return
			}
		}

		//  TODO(teawithsand): make this test pass
		// 2. Invalid overlap(should not crash)
		/*
			{
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
			}
		*/

		return
	}

	run := func(rng io.Reader) {

		// 1. Small single chunk
		for i := 0; i < 32; i++ {
			assert(test(makeTestChunks(rand.ZeroRNG(), i)[0]))
		}
	}
	run(rand.ZeroRNG())
	run(rand.DefaultRNG())

}
