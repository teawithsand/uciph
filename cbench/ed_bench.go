package cbench

import (
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/rand"
)

type EDBenchRunConfig struct {
	Name  string
	RNG   rand.RNG
	Sizes []int

	InPlace bool
}

// EDBenchConfig configures how should encryptor and decryptor be benchmarked.
type EDBenchConfig struct {
	RNG rand.RNG // RNG to fill chunks, may be overridden in EDBenchRunConfig

	Runs []EDBenchRunConfig
}

// EDBenchEngine benchmarks encryption/decryption process.
type EDBenchEngine struct {
	Fac         func() (enc.Encryptor, enc.Decryptor)
	Config      EDBenchConfig
	Paralellism int // zero defaults to 1, <0 defaults to runtime.NumCPU()
}

/*
// DefaultEDBenchConfig provides reasonable defaults for benchmarking purposes of any encryptor/decryptor.
var DefaultEDBenchConfig = EDBenchConfig{
	RNG:  rand.DefaultRNG(),
	Runs: GenereateDefaultRuns(),
}
*/

// GenereateDefaultEDRuns generates reasonable defaults for EDBenchConfig.
func GenereateDefaultEDRuns(
	doDependOnRNG bool,
) []EDBenchRunConfig {
	res := make([]EDBenchRunConfig, 0)

	for _, size := range []int{
		1, 512, 1024, 4096, 1024 * 1024 / 2, 1024 * 1024, 1024 * 1024 * 8,
	} {
		for _, chunkCount := range []int{
			1, 2, 8, 1024,
		} {
			var rngs []rand.RNG
			if doDependOnRNG {
				rngs = []rand.RNG{
					rand.ZeroRNG(),
					rand.DefaultRNG(),
					rand.FastRNG(123),
				}
			} else {
				rngs = []rand.RNG{
					rand.ZeroRNG(),
				}
			}
			for rngI, rng := range rngs {
				var rngText string
				if len(rngs) == 1 {
					rngText = "NORNG"
				} else if rngI == 0 {
					rngText = "ZERO"
				} else if rngI == 1 {
					rngText = "DEFAULT"
				} else {
					rngText = "FAST(123)"
				}

				for _, inPlace := range []bool{true, false} {
					var inplace string
					if inPlace {
						inplace = "INPLACE"
					} else {
						inplace = "ALLOC"
					}
					res = append(res, EDBenchRunConfig{
						Name:    fmt.Sprintf("%dB_%dC_RNG:%s_%s", size, chunkCount, rngText, inplace),
						RNG:     rng,
						InPlace: inPlace,
						Sizes:   EqualChunkSizes(size, chunkCount),
					})
				}
			}
		}
	}

	return res
}

// TODO(teawithsand): add benchmark for encrypt/decrypt only

func (e *EDBenchEngine) RunEDBenchmark(b *testing.B) {
	if e.Paralellism > 0 {
		b.SetParallelism(e.Paralellism)
	}
	if e.Paralellism < 0 {
		b.SetParallelism(runtime.NumCPU())
	}
	for _, run := range e.Config.Runs {
		var r io.Reader = e.Config.RNG
		if run.RNG != nil {
			r = run.RNG
		}
		if r == nil {
			r = rand.DefaultRNG()
		}

		chunks, err := MakeTestChunks(r, run.Sizes...)
		if err != nil {
			b.Error(err)
			return
		}

		e, d := e.Fac()

		var ss int64
		for _, c := range chunks {
			ss += int64(len(c))
		}

		b.Run(run.Name, func(b *testing.B) {
			b.SetBytes(ss)
			for j := 0; j < b.N; j++ {
				if run.InPlace {
					for i, c := range chunks {
						var err error
						chunks[i], err = e.Encrypt(c[:], c[:0])
						if err != nil {
							b.Error(err)
							return
						}
					}
					for i, c := range chunks {
						var err error
						chunks[i], err = d.Decrypt(c[:], c[:0])
						if err != nil {
							b.Error(err)
							return
						}
					}
				} else {

					for i, c := range chunks {
						var err error
						chunks[i], err = e.Encrypt(c[:], nil)
						if err != nil {
							b.Error(err)
							return
						}
					}
					for i, c := range chunks {
						var err error
						chunks[i], err = d.Decrypt(c[:], nil)
						if err != nil {
							b.Error(err)
							return
						}
					}
				}
			}
		})
	}
}
