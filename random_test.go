package uciph_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/teawithsand/uciph"
)

func BenchmarkDefaultRNG(b *testing.B) {
	benchmarkRNG(b, func() io.Reader { return uciph.DefaultRNG })
}

func BenchmarkFastRNG(b *testing.B) {
	benchmarkRNG(b, func() io.Reader {
		return uciph.FastRNG(12345) // some seed, it should not matter(?)
	})
}

func BenchmarkChaCha20RNG(b *testing.B) {
	benchmarkRNG(b, func() io.Reader {
		r, err := uciph.NewChaCha20RNG(make([]byte, 32)) // some seed, it should not matter(?)
		if err != nil {
			panic(err)
		}
		return r
	})
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

	g1, err := uciph.NewChaCha20RNG(s1)
	noError()
	g2, err := uciph.NewChaCha20RNG(s2)
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

	g1, err := uciph.NewChaCha20RNG(s1)
	noError()
	g2, err := uciph.NewChaCha20RNG(s2)
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

	g1, err := uciph.NewChaCha20RNG(s1)
	noError()
	g2, err := uciph.NewChaCha20RNG(s2)
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
