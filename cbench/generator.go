package cbench

import "io"

// MakeTestChunks allocates chunks with corresponding sizes.
// It fills them with data from io.Reader it's given.
// Usually it's some kind of RNG.
func MakeTestChunks(r io.Reader, sizes ...int) (res [][]byte, err error) {
	res = make([][]byte, len(sizes))
	defer func() {
		if err != nil {
			res = nil // make sure that res won't be allocated for too long - during error handling
		}
	}()
	for i, sz := range sizes {
		res[i] = make([]byte, sz)
		_, err = io.ReadFull(r, res[i])
		if err != nil {
			return
		}
	}
	return
}

// EqualChunkSizes creates slice of chunk sizes.
// It's used to express size in specifeid amount of chunks.
// First N chunks have size equal to totalSize / chunkCount and last one is smaller.
// Last one is ommited if totalSize % chunkCount == 0.
func EqualChunkSizes(totalSize, chunkCount int) []int {
	cs := totalSize / chunkCount
	rem := totalSize % chunkCount

	res := make([]int, 0, chunkCount)
	if cs != 0 {
		for i := 0; i < chunkCount; i++ {
			res = append(res, cs)
		}
	}
	if rem != 0 {
		res = append(res, rem)
	}
	return res
}
