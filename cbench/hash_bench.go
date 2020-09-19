package cbench

import (
	"testing"

	"github.com/teawithsand/uciph/rand"
	"github.com/teawithsand/uciph/sig"
)

type HashBenchRunConfig struct {
	Name       string
	Sizes      []int
	FinalizeTo []byte // if nil then ignored
}

// HashBenchConfig configures how should encryptor and decryptor be benchmarked.
type HashBenchConfig struct {
	Runs []HashBenchRunConfig
}

// HashBenchEngine runs benchmarks of specified Hash.
type HashBenchEngine struct {
	Fac    func() sig.Hasher
	Config HashBenchConfig
}

// TODO(teawithsand): config generation function

func (e *HashBenchEngine) RunHashBenchmark(b *testing.B) {
	for _, run := range e.Config.Runs {
		hasher := e.Fac()
		chunks, err := MakeTestChunks(rand.DefaultRNG(), run.Sizes...)
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
					_, err := hasher.Write(c[:])
					if err != nil {
						b.Error(err)
						return
					}
				}
			}
			if run.FinalizeTo != nil {
				_, err = hasher.Finalize(run.FinalizeTo)
				if err != nil {
					return
				}
			}
		})
	}
}
