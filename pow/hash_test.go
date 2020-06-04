package pow_test

import (
	"context"
	"crypto"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/teawithsand/uciph/pow"
	"github.com/teawithsand/uciph/sig"

	_ "crypto/sha512"
)

func TestHashBasedPOW_WhenDifficulyLow_IsSolvable(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	// this test is propabilistic(somehow)
	// and should be repeated a few times
	for i := 0; i < 5; i++ {
		d := big.NewInt(2)
		bits := big.NewInt(512)
		bits = bits.Sub(bits, big.NewInt(15))
		d = d.Exp(d, bits, nil)
		hf, err := sig.NewCryptoHasherFac(crypto.SHA512)
		if err != nil {
			t.Error(err)
		}
		g, c, err := pow.NewHashGen(d.Bytes(), hf, nil)
		if err != nil {
			t.Error(err)
		}
		s, err := pow.NewHashSolver(d.Bytes(), hf, nil)
		if err != nil {
			t.Error(err)
		}
		chal, err := g.GenChal(nil, nil)
		if err != nil {
			t.Error(err)
		}
		sol, err := s.SolveChal(ctx, nil, chal, nil)
		if err != nil {
			t.Error(err)
		}
		err = c.CheckChal(nil, chal, sol)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestHashBasedPow_WhenDifficultyIsBig_IsNotSolvable(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	// this test is propabilistic(somehow)
	// and should be repeated a few times
	// but it also takes long
	// so run it once

	d := big.NewInt(2)
	bits := big.NewInt(512)
	bits = bits.Sub(bits, big.NewInt(300))
	d = d.Exp(d, bits, nil)
	hf, err := sig.NewCryptoHasherFac(crypto.SHA512)
	if err != nil {
		t.Error(err)
	}
	g, _, err := pow.NewHashGen(d.Bytes(), hf, nil)
	if err != nil {
		t.Error(err)
	}
	s, err := pow.NewHashSolver(d.Bytes(), hf, nil)
	if err != nil {
		t.Error(err)
	}
	chal, err := g.GenChal(nil, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = s.SolveChal(ctx, nil, chal, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		if err == nil {
			err = errors.New("This should be hard and not solvable, so this probably is bug")
		}
		t.Error(err)
	}
}
