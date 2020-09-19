package fuzzpackage

import (
	"github.com/teawithsand/uciph/cutil"
)

// Fuzz is testing fuzz method.
// It's example implementation created in order to check if code changes are reflected after doing fuzzbuild.
// Uncomment panic line in cutil.NonceCounter.Increment() in order to check if it works.
func Fuzz(data []byte) int {
	nc := cutil.NonceCounter(make([]byte, 123))
	err := nc.Increment()
	if err != nil {
		panic("got error: " + err.Error())
	}
	return 0
}
