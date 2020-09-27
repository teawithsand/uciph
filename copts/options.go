package copts

import (
	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/rand"
)

// Options is structure, which handles all options, that are used in uciph.
type Options struct {
	NonceMode enc.NonceMode
	RNG       rand.RNG
}

func getOpts(o *Options) Options {
	if o == nil {
		return Options{}
	}
	return *o
}

func (o Options) WithRNG(rng rand.RNG) Options {
	no := getOpts(&o)
	no.RNG = rng
	return no
}

func (o Options) WithNonceMode(nm enc.NonceMode) Options {
	no := getOpts(&o)
	no.NonceMode = nm
	return no
}

func (o *Options) GetNonceMode() enc.NonceMode {
	if o.NonceMode == 0 {
		return enc.NonceModeDefault
	}
	return o.NonceMode
}

func (o *Options) GetRNG() rand.RNG {
	if o.RNG == nil {
		return rand.DefaultRNG()
	}
	return o.RNG
}
