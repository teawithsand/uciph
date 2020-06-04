package pow

import (
	"context"
	"errors"
	"io"
	"math/big"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"github.com/teawithsand/uciph/sig"
	"github.com/teawithsand/uciph/util"
)

// NewHashGen creates hash-based proof of work generator.
// In order to pass test, hashed value has to be lower than diff num interpreted as be bytes using
// math/big.Int from golang's stl.
func NewHashGen(diffNum []byte, hf sig.HasherFac, options interface{}) (g Gen, c Checker, err error) {
	g = GenFunc(func(options interface{}, appendTo []byte) (res []byte, err error) {
		var suffix [32]byte
		rng := rand.GetRNG(options)
		_, err = io.ReadFull(rng, suffix[:])
		if err != nil {
			return
		}
		res = append(appendTo, suffix[:]...)
		return
	})

	lim := big.NewInt(0).SetBytes(diffNum)

	c = CheckerFunc(func(options interface{}, challenge, solution []byte) (err error) {
		var buf [64]byte // 64 is enough for typical hash values to not allocate on heap
		h, err := hf.NewHasher(options)
		if err != nil {
			return
		}

		_, err = h.Write(solution)
		if err != nil {
			return
		}

		_, err = h.Write(challenge)
		if err != nil {
			return
		}

		sum, err := h.Sum(buf[:0])
		if err != nil {
			return
		}
		val := big.NewInt(0).SetBytes(sum)

		// if val is lower than or equal to limit
		if val.Cmp(lim) <= 0 {
			// then solution is valid
		} else {
			// or solution is not valid
			err = uciph.ErrPowInvalid
		}

		return
	})
	return
}

// NewHashSolver creates solver for hash-based proof of work generator.
// Note: in order for this to work caller has to pass same diffNum and hf
// which were passed to newHashGen.
//
// Note2: This solver is CPU based and not the most performant one, so for real world testing other PoWs should
// be used or GPU based solver should be linked in using CGO(should work with cuda like this).
func NewHashSolver(diffNum []byte, hf sig.HasherFac, options interface{}) (s Solver, err error) {
	// TOOD(teawithsand): make it true
	// Note: Solver always uses single writes to hasher's hash function, which can be optimized
	// for specific hash function implementation.

	lim := big.NewInt(0).SetBytes(diffNum)
	val := big.NewInt(0)
	s = SolverFunc(func(ctx context.Context, options interface{}, challenge, appendTo []byte) (res []byte, err error) {
		nc := util.NonceCounter(make([]byte, 1, 4))
		buf := make([]byte, 64)
		for {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				return
			default:
			}

			var h sig.Hasher
			h, err = hf.NewHasher(options)
			if err != nil {
				return
			}

			_, err = h.Write(nc[:])
			if err != nil {
				return
			}

			_, err = h.Write(challenge)
			if err != nil {
				return
			}

			buf, err = h.Sum(buf[:0])
			if err != nil {
				return
			}

			val = val.SetBytes(buf)
			if val.Cmp(lim) <= 0 {
				res = append(appendTo, nc[:]...)
				return
			}

			err = nc.Increment()
			if errors.Is(err, uciph.ErrTooManyChunksEncrypted) {
				// increase NC length
				nc = append(nc, 0)

				// and zero it out
				for i := 0; i < len(nc); /*-1*/ i++ {
					nc[i] = 0
				}
			} else if err != nil {
				return
			}
		}
	})

	return
}
