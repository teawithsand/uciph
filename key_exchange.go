package uciph

type KXGenOptions = interface{}

// KXGen generates key exchange
type KXGen interface {
	GenKX(options KXGenOptions) (pub, sec []byte, err error)
}

// KXGenFunc is KXGen but in function.
// Once can cast function to this type to satisfy KXGen interface.
type KXGenFunc func(options KXGenOptions) (pub, sec []byte, err error)

func (f KXGenFunc) GenKX(options KXGenOptions) (pub, sec []byte, err error) {
	return f(options)
}

// PubKXParser parses public part of key exchange algorithm.
type PubKXParser interface {
	ParsePubKX(data []byte) (PubKX, error)
}

// PubKX is public part of key exchange algorithm.
type PubKX interface {
}

// SecKXParser parses secret part of key exchange algorithm.
type SecKXParser interface {
	ParseSecKX(data []byte) (SecKX, error)
}

// KXParser parses both public and secret part of key exchange algorithm.
type KXParser interface {
	PubKXParser
	SecKXParser
}

// MixWithPubOptions contains options passed to secret key exchange key.
type MixWithPubOptions = interface{}

// SecKX is secret part of key exchange algorithm.
// It's able to mix itself with
type SecKX interface {
	MixWithPub(pubKX PubKX, options MixWithPubOptions, appendTo []byte) (data []byte, err error)
}
