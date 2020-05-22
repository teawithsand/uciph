package fuzz

import (
	"github.com/teawithsand/uciph"
)

var sz int

func Fuzz(data []byte) int {
	sz = uciph.IEC78164Padding.Unpad(data)
	return 0
}
