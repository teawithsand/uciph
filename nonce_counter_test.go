package uciph

import (
	"fmt"
	"testing"
)

func TestTwoByteNonceCounterUnique(t *testing.T) {
	nc := NonceCounter(make([]byte, 2))
	aggregated := make(map[[2]byte]struct{})
	i := 0
	for {
		err := nc.Increment()
		if err != nil {
			break
		}
		var arr [2]byte
		copy(arr[:], nc[:])

		_, ok := aggregated[arr]
		if ok {
			t.Error("Counter value found twice!")
		}
		aggregated[arr] = struct{}{}
		i++
	}
	if i != 0xffff {
		t.Error(fmt.Sprintf("Invalid i value: %d", i))
	}
}

func TestThreeByteNonceCounterFails(t *testing.T) {
	nc := NonceCounter(make([]byte, 3))
	for {
		err := nc.Increment()
		if err != nil {
			break
		}
	}
}
