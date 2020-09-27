package ctest

import (
	"bytes"
	"errors"
	"testing"

	"github.com/teawithsand/uciph/sig"
)

func DoTestHasher(
	t *testing.T,
	hashf func() sig.Hasher,
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
			s1, err := h1.Finalize(nil)
			if err != nil {
				return
			}
			s2, err := h2.Finalize(nil)
			if err != nil {
				return
			}

			if bytes.Compare(s1, s2) != 0 {
				err = errors.New("Slices are not equal")
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
			s1, err := h1.Finalize(nil)
			if err != nil {
				return
			}
			s2, err := h2.Finalize(nil)
			if err != nil {
				return
			}

			if bytes.Compare(s1, s2) != 0 {
				err = errors.New("Slices are not equal")
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
