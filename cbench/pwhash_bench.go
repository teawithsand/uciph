package cbench

import (
	"testing"

	"github.com/teawithsand/uciph/cutil/pwhash"
)

type PWHashBenchRunConfig struct {
	Name     string
	Password []byte //defaults to []byte("Password")
	Data     interface{}
}

// PWHashBenchConfig configures how should encryptor and decryptor be benchmarked.
type PWHashBenchConfig struct {
	Runs []PWHashBenchRunConfig
}

// PWHashBenchEngine runs benchmarks of specified PWHash.
type PWHashBenchEngine struct {
	Fac    func(rc PWHashBenchRunConfig) pwhash.Hasher
	Config PWHashBenchConfig
}

// TODO(teawithsand): config generation function

func (e *PWHashBenchEngine) RunPWHashBenchmark(b *testing.B) {
	for _, run := range e.Config.Runs {
		hasherFunc := e.Fac(run)
		password := run.Password
		if len(password) == 0 {
			password = []byte("Password")
		}

		b.Run(run.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hasherFunc(password)
			}
		})
	}
}
