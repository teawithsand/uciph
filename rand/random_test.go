package rand_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/rand"
)

// FastRNG is STL rng so no more tests.
func TestFastRNG_HasSameOutput_WhenSeedSame(t *testing.T) {
	r1 := rand.FastRNG(1234)
	r2 := rand.FastRNG(1234)
	for i := 0; i < 100; i++ {
		b1 := make([]byte, 1024)
		b2 := make([]byte, 1024)
		_, err := io.ReadFull(r1, b1[:])
		if err != nil {
			t.Error(err)
		}

		_, err = io.ReadFull(r2, b2[:])
		if err != nil {
			t.Error(err)
		}

		if bytes.Compare(b1, b2) != 0 {
			t.Error("Slices different!")
		}
	}
}

func TestChaCha20RNG_HasSameOutput_WhenSeedSame(t *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)

	var err error
	noError := func() {
		if err != nil {
			t.Error(err)
		}
	}

	g1, err := rand.NewChaCha20RNG(s1)
	noError()
	g2, err := rand.NewChaCha20RNG(s2)
	noError()

	var b1 [4096]byte
	var b2 [4096]byte
	_, err = io.ReadFull(g1, b1[:])
	noError()

	_, err = io.ReadFull(g2, b2[:])
	noError()

	if bytes.Compare(b1[:], b2[:]) != 0 {
		t.Error("Slices are not equal")
	}
}

func TestChaCha20RNG_HasSameOutput_WhenCallsAreSpread(t *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)

	var err error
	noError := func() {
		if err != nil {
			t.Error(err)
		}
	}

	g1, err := rand.NewChaCha20RNG(s1)
	noError()
	g2, err := rand.NewChaCha20RNG(s2)
	noError()

	var b1 [4096]byte
	var b2 [4096]byte
	_, err = g1.Read(b1[:])
	noError()

	for i := 0; i < len(b2); i += 1024 {
		_, err = g2.Read(b2[i : i+1024])
		noError()
	}

	if bytes.Compare(b1[:], b2[:]) != 0 {
		t.Error("Slices are not equal")
	}
}

func TestChaCha20RNG_HasDifferentOutput_WhenSeedDiffer(t *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	s2[0] = 1

	var err error
	noError := func() {
		if err != nil {
			t.Error(err)
		}
	}

	g1, err := rand.NewChaCha20RNG(s1)
	noError()
	g2, err := rand.NewChaCha20RNG(s2)
	noError()

	var b1 [4096]byte
	var b2 [4096]byte
	_, err = io.ReadFull(g1, b1[:])
	noError()

	_, err = io.ReadFull(g2, b2[:])
	noError()

	if bytes.Compare(b1[:], b2[:]) == 0 {
		t.Error("Slices are equal")
	}
}

func BenchmarkDefaultRNG(b *testing.B) {
	e := cbench.RNGBenchEngine{
		Fac: func() rand.RNG { return rand.DefaultRNG() },
		Config: cbench.RNGBenchConfig{
			Runs: cbench.GenerateDefaultRNGRuns(),
		},
	}

	e.RunRNGBenchmark(b)
}

func BenchmarkFastRNG(b *testing.B) {
	e := cbench.RNGBenchEngine{
		Fac: func() rand.RNG { return rand.DefaultRNG() },
		Config: cbench.RNGBenchConfig{
			Runs: cbench.GenerateDefaultRNGRuns(),
		},
	}

	e.RunRNGBenchmark(b)
}

func BenchmarkChaCha20RNG(b *testing.B) {
	e := cbench.RNGBenchEngine{
		Fac: func() rand.RNG {
			r, err := rand.NewChaCha20RNG(make([]byte, 32)) // some seed, it should not matter(?)
			if err != nil {
				panic(err)
			}
			return r
		},
		Config: cbench.RNGBenchConfig{
			Runs: cbench.GenerateDefaultRNGRuns(),
		},
	}

	e.RunRNGBenchmark(b)
}
