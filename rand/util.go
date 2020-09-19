package rand

type readerFunc func(buf []byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) {
	return f(b)
}
