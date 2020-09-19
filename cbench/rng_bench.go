package cbench

import (
	"fmt"
	"io"
	"testing"

	"github.com/teawithsand/uciph/rand"
)

type RNGBenchRunConfig struct {
	Name  string
	Sizes []int
}

// RNGBenchConfig configures how should encryptor and decryptor be benchmarked.
type RNGBenchConfig struct {
	Runs []RNGBenchRunConfig
}

// RNGBenchEngine runs benchmarks of specified RNG.
type RNGBenchEngine struct {
	Fac    func() rand.RNG
	Config RNGBenchConfig
}

func GenerateDefaultRNGRuns() []RNGBenchRunConfig {
	res := make([]RNGBenchRunConfig, 0)
	for _, size := range []int{
		1, 512, 1024, 4096, 1024 * 1024 / 2, 1024 * 1024, 1024 * 1024 * 8,
	} {
		for _, chunkCount := range []int{
			1, 2, 8, 1024,
		} {
			res = append(res, RNGBenchRunConfig{
				Name:  fmt.Sprintf("%dB_%dC", size, chunkCount),
				Sizes: EqualChunkSizes(size, chunkCount),
			})
		}
	}
	return res
}

func (e *RNGBenchEngine) RunRNGBenchmark(b *testing.B) {
	for _, run := range e.Config.Runs {
		rng := e.Fac()
		chunks, err := MakeTestChunks(rand.ZeroRNG(), run.Sizes...)
		if err != nil {
			b.Error(err)
			return
		}

		var ss int64
		for _, c := range chunks {
			ss += int64(len(c))
		}

		b.Run(run.Name, func(b *testing.B) {
			b.SetBytes(ss)
			for i := 0; i < b.N; i++ {
				for _, c := range chunks {
					_, err := io.ReadFull(rng, c[:])
					if err != nil {
						b.Error(err)
						return
					}
				}
			}
		})
	}
}
