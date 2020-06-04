package sig_test

import (
	"fmt"
	"testing"

	"github.com/teawithsand/uciph/sig"
)

func BenchmarkRSAKeygen(b *testing.B) {
	r := func(sz int) {
		kg, err := sig.RSAKeygen(sz)
		if err != nil {
			b.Error(err)
		}
		b.Run(fmt.Sprintf("%d_with_default_rng", sz), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := kg.GenSigKey(nil, nil, nil)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
	r(1024)
	r(1024 * 2)
	r(1024 * 4)
}
