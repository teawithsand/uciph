package kx

// Gen generates key exchange
type Gen interface {
	GenKX(options interface{}, pubAppendTo, secAppendTo []byte) (pub, sec []byte, err error)
}

// GenFunc is KXGen but in function.
// Once can cast function to this type to satisfy KXGen interface.
type GenFunc func(options interface{}, pubAppendTo, secAppendTo []byte) (pub, sec []byte, err error)

// GenKX makes KXGenFunc satisfy KXGen.
func (f GenFunc) GenKX(options interface{}, pubAppendTo, secAppendTo []byte) (pub, sec []byte, err error) {
	return f(options, pubAppendTo, secAppendTo)
}

// PubParser parses public part of key exchange algorithm.
type PubParser interface {
	ParsePubKX(data []byte) (Pub, error)
}

// Pub is public part of key exchange algorithm.
type Pub interface {
}

// SecParser parses secret part of key exchange algorithm.
type SecParser interface {
	ParseSecKX(data []byte) (Sec, error)
}

// Parser parses both public and secret part of key exchange algorithm.
type Parser interface {
	PubParser
	SecParser
}

// Sec is secret part of key exchange algorithm.
// It's able to mix itself with
type Sec interface {
	MixWithPub(pubKX Pub, options interface{}, appendTo []byte) (data []byte, err error)
}
