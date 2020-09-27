package kx_test

import (
	"testing"

	"github.com/teawithsand/uciph/ctest"
	"github.com/teawithsand/uciph/kx"
)

func TestCurve25519KX(t *testing.T) {
	ctest.DoTestKX(t, kx.GenCurve25519, kx.Curve25519)
}
