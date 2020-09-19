package fuzzpackage

import (
	"github.com/teawithsand/uciph/cutil"
)

// Fuzz is testing fuzz method.
// This is another example implementation, which is supposed to test nonce counter.
func Fuzz(data []byte) int {
	nc := cutil.NonceCounter(data)
	_ = nc.Increment()
	return 0
}
