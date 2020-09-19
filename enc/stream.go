package enc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/teawithsand/uciph"
)

type intEncoding int8

func (e intEncoding) IsValid() bool {
	return e == ByteVar || e == Byte1 || e == Byte2 || e == Byte4 || e == Byte8
}

func (e intEncoding) Size(n uint64) int {
	var arr [10]byte
	switch e {
	case ByteVar:
		s := binary.PutUvarint(arr[:], n)
		return s
	case Byte1:
		if n > (1<<8)-1 {
			return -1
		}
		return 1
	case Byte2:
		if n > (1<<16)-1 {
			return -1
		}
		return 1
	case Byte4:
		if n > (1<<32)-1 {
			return -1
		}
		return 1
	case Byte8:
		if n > (1<<64)-1 {
			return -1
		}
		return 1
	default:
		return -1
	}
}

func (e intEncoding) Encode(buf []byte, n uint64) (sz int) {
	switch e {
	case ByteVar:
		sz = binary.PutUvarint(buf, n)
	case Byte1:
		buf[0] = byte(n)
	case Byte2:
		sz = 2
		binary.BigEndian.PutUint16(buf, uint16(n))
	case Byte4:
		sz = 4
		binary.BigEndian.PutUint32(buf, uint32(n))
	case Byte8:
		sz = 8
		binary.BigEndian.PutUint64(buf, n)
	default:
		sz = -1
	}
	return
}

type byteReaderExt struct {
	R io.Reader
}

func (r byteReaderExt) ReadByte() (b byte, err error) {
	var arr [1]byte

	_, err = io.ReadFull(r.R, arr[:])
	if err != nil {
		return
	}

	b = arr[0]
	return
}

func (e intEncoding) Decode(r io.Reader) (n uint64, err error) {
	var b byte

	var br io.ByteReader
	var ok bool
	if br, ok = r.(io.ByteReader); ok {
	} else {
		br = byteReaderExt{R: r}
	}

	switch e {
	case ByteVar:
		return binary.ReadUvarint(br)
	case Byte1:
		b, err = br.ReadByte()
		if err != nil {
			return
		}
		n = uint64(b)
	case Byte2:
		var arr [2]byte
		_, err = io.ReadFull(r, arr[:])
		if err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(arr[:]))
	case Byte4:
		var arr [4]byte
		_, err = io.ReadFull(r, arr[:])
		if err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint32(arr[:]))
	case Byte8:
		var arr [8]byte
		_, err = io.ReadFull(r, arr[:])
		if err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint64(arr[:]))
	default:
		panic("NIY ERROR HERE INVALID INT ENCODING")
	}
	return
}

const (
	// ByteVar note: in order to encode all ints it may take up to 9 bytes
	ByteVar intEncoding = 0 //default is variable
	Byte1   intEncoding = 1
	Byte2   intEncoding = 2
	Byte4   intEncoding = 4
	Byte8   intEncoding = 8
)

type defaultStreamEncryptor struct {
	DstBufferSize int

	CurrentEncBufferSize int
	EncBuffer            []byte // It's preallocated and may have variable length due to in-place necryption

	Encryptor Encryptor

	ChunkCounter         uint64
	ChunkCounterEncoding intEncoding
	ChunkLengthEncoding  intEncoding

	Sink io.Writer

	ErrorCache error
}

func (dse *defaultStreamEncryptor) Close() (err error) {
	if dse.ErrorCache != nil {
		return dse.ErrorCache
	}
	defer func() {
		if err != nil {
			dse.ErrorCache = err
		}
	}()
	defer func() {
		if err == nil {
			dse.ErrorCache = errors.New("TODO ERROR STREAM ENCRYPTOR HAS BEEN CLOSED")
		}
	}()

	if dse.CurrentEncBufferSize > 0 {
		// Enc buffer already contains size(if it's required)
		// do not write it to enc buffer here
		var buffer []byte
		buffer, err = dse.Encryptor.Encrypt(dse.EncBuffer[:dse.CurrentEncBufferSize], dse.EncBuffer[:0])
		if err != nil {
			return
		}

		// Write length if required
		{
			var sizeBuffer [10]byte
			if dse.ChunkLengthEncoding.IsValid() {
				sz := dse.ChunkCounterEncoding.Encode(sizeBuffer[:], uint64(len(buffer)))
				_, err = dse.Sink.Write(buffer[:sz])
				if err != nil {
					return
				}
			}
		}

		// and then write chunk
		_, err = dse.Sink.Write(buffer)
		if err != nil {
			return
		}
	}

	// Write terminator chunk if required
	if dse.ChunkCounterEncoding.IsValid() {
		// TODO(teawithsand): encrypt chunk counter with zero value and then write it's length
		// it's much better terminator chunk
		var sizeBuffer [9]byte
		if dse.ChunkLengthEncoding.IsValid() {
			writtenSz := dse.ChunkCounterEncoding.Encode(sizeBuffer[:], uint64(0))
			_, err = dse.Sink.Write(sizeBuffer[:writtenSz])
			if err != nil {
				return
			}
		}
	}
	return
}

func (dse *defaultStreamEncryptor) Write(data []byte) (sz int, err error) {
	if dse.ErrorCache != nil {
		return 0, dse.ErrorCache
	}
	defer func() {
		if err != nil {
			dse.ErrorCache = err
		}
	}()
	sz = len(data)

	// do not allow empty chunks
	if len(data) == 0 {
		return
	}

	if dse.DstBufferSize <= 0 {
		// Allocate + encrypt here
		// rather than use buffer, since data length is variable
		// alternative is encBuffer with size equal to max passed chunk size
		// or do some hybrid for usual chunk sizes
		// right now it allocates always

		bufSz := 0
		numOffset := 0
		if dse.ChunkCounterEncoding.IsValid() {
			sz := dse.ChunkCounterEncoding.Size(dse.ChunkCounter)
			if sz < 0 {
				// TODO(teawithsand): return error here
				panic("NIY INVALID SIZE")
			}
			numOffset = sz
			bufSz += sz
		}
		bufSz += len(data)

		buffer := make([]byte, bufSz)

		// 1. Write chunk counter into buffer if enabled
		if dse.ChunkCounterEncoding >= 0 {
			sz := dse.ChunkCounterEncoding.Encode(dse.EncBuffer, dse.ChunkCounter)
			dse.CurrentEncBufferSize += sz
		}
		dse.ChunkCounter++

		// 2. Copy data to buffer
		copy(buffer[numOffset:], data) // this always copies whole data buffer

		// 3. Encrypt in place
		buffer, err = dse.Encryptor.Encrypt(buffer, buffer[:0])
		if err != nil {
			return
		}

		// 4.0 Write chunk length(if required)
		{
			var sizeBuffer [9]byte
			if dse.ChunkLengthEncoding.IsValid() {
				writtenSz := dse.ChunkCounterEncoding.Encode(sizeBuffer[:], uint64(len(buffer)))
				_, err = dse.Sink.Write(buffer[:writtenSz])
				if err != nil {
					return
				}
			}
		}

		// 4.1 Write data to sink
		_, err = dse.Sink.Write(buffer)
		if err != nil {
			return
		}
	} else {
		for len(data) > 0 {
			// 1. Write chunk counter into buffer if enabled
			if dse.CurrentEncBufferSize == 0 && dse.ChunkCounterEncoding >= 0 {
				sz := dse.ChunkCounterEncoding.Encode(dse.EncBuffer, dse.ChunkCounter)
				dse.CurrentEncBufferSize += sz
			}

			// TOOD(teawithsnad): optimize: when there is no data in EncBuffer
			// then simply get data directly from data variable and specify EncBuffer as destination.
			// although it's not that simple when

			// 2. Fill encryption buffer with data
			copiedSz := copy(dse.EncBuffer[dse.CurrentEncBufferSize:dse.DstBufferSize], data[:])
			dse.CurrentEncBufferSize += copiedSz

			// note: possible state corruption if no error caching
			data = data[copiedSz:]

			// 3. If buffer is filled do encrypt in place and
			// set it's current size to zero
			if dse.CurrentEncBufferSize == dse.DstBufferSize {
				dse.ChunkCounter++ // again, possible state corruption if no error caching

				var res []byte
				res, err = dse.Encryptor.Encrypt(dse.EncBuffer[:], dse.EncBuffer[:0])
				if err != nil {
					return
				}

				// Write chunk length(if required)
				{
					var sizeBuffer [9]byte
					if dse.ChunkLengthEncoding.IsValid() {
						writtenSz := dse.ChunkCounterEncoding.Encode(sizeBuffer[:], uint64(len(dse.EncBuffer)))
						_, err = dse.Sink.Write(sizeBuffer[:writtenSz])
						if err != nil {
							return
						}
					}
				}

				// note: state may be corrupted if error is not cached
				// so it has to be cached
				dse.CurrentEncBufferSize = 0

				_, err = dse.Sink.Write(res)
				if err != nil {
					return
				}
			}
		}
	}

	return
}

type defaultStreamDecryptor struct {
	DstBufferSize int

	CurrentDecBufferSize int
	DecBuffer            []byte

	Decryptor Decryptor

	// ChunkCounter is maintained in order to check chunks consistenct
	ChunkCounter         uint64
	ChunkCounterEncoding intEncoding
	ChunkLengthEncoding  intEncoding
	MaxBufferSize        uint64 // Enabled only when chunk size is read from data.

	Source io.Reader

	ErrorCache error
}

func (asd *defaultStreamDecryptor) IsDone() bool {
	return asd.ErrorCache != nil
}

func (asd *defaultStreamDecryptor) Close() (err error) {
	if asd.ErrorCache == io.EOF {
		return nil
	} else if asd.ErrorCache != nil {
		err = asd.ErrorCache
	} else {
		asd.ErrorCache = uciph.ErrStreamTruncated
		err = asd.ErrorCache
	}

	return
}

func (asd *defaultStreamDecryptor) Read(buf []byte) (sz int, err error) {
	if asd.ErrorCache != nil {
		return 0, asd.ErrorCache
	}
	defer func() {
		if err != nil {
			asd.ErrorCache = err
		}
	}()

	// ignore empty reads
	if len(buf) == 0 {
		return
	}

	copyDataSize := copy(buf, asd.DecBuffer[:asd.CurrentDecBufferSize])
	buf = buf[copyDataSize:]

	asd.DecBuffer = asd.DecBuffer[copyDataSize:]
	asd.CurrentDecBufferSize -= copyDataSize
	sz += copyDataSize

	// Free previous buffer
	if len(asd.DecBuffer) == 0 {
		asd.DecBuffer = nil
	}

	// Load data from Source in order to try to fill buf.
	for len(buf) > 0 {
		// 1. Read chunk length
		// If not available fallback to asd.DstBufferSize
		var chunkLength int
		if asd.ChunkLengthEncoding.IsValid() {
			var len uint64
			len, err = asd.ChunkLengthEncoding.Decode(asd.Source)
			if err != nil {
				return
			}
			if asd.MaxBufferSize != 0 && len > asd.MaxBufferSize {
				err = uciph.ErrChunkTooBig
				return
			}

			chunkLength = int(len)
		} else {
			chunkLength = asd.DstBufferSize
		}

		// cache it for small sizes?
		// using variable in struct

		// 2. Allocate buffer for new chunk and read data into it
		chunkBuffer := make([]byte, chunkLength)
		_, err = io.ReadFull(asd.Source, chunkBuffer)
		if err != nil {
			return
		}

		// 3. Perform actual decryption
		chunkBuffer, err = asd.Decryptor.Decrypt(chunkBuffer, chunkBuffer[:0])
		if err != nil {
			return
		}

		// 4. Maintain chunk coutner(if any)
		if asd.ChunkCounterEncoding.IsValid() {
			var chunkCounter uint64
			chunkCounter, err = asd.ChunkLengthEncoding.Decode(bytes.NewReader(chunkBuffer))
			if err != nil {
				return
			}

			chunkCounterSize := asd.ChunkLengthEncoding.Size(chunkCounter)

			// It's terminator chunk.
			if chunkCounter == 0 {
				if len(chunkBuffer) != chunkCounterSize {
					// Invalid chunk counter value! Finalize chunk must not contain any data!
					err = errors.New("stream: TODO error invalid chunk counter value")
					return
				}
				if sz <= 0 {
					// no data read in total so just return EOF
					err = io.EOF
				} else {
					// some data has been already written
					// so do not return error
					// return it on next call to read
					asd.ErrorCache = io.EOF
				}
				return
			}

			if chunkCounter != asd.ChunkCounter {
				// Chunk counter mismatch!
				err = uciph.ErrStreamChunksReordered
				return
			}

			// Trim chunkBuffer, so it contians only useful data.
			chunkBuffer = chunkBuffer[chunkCounterSize:]
		}

		// 5. Copy data into buffer and set data
		writtenSz := copy(buf, chunkBuffer)
		chunkBuffer = chunkBuffer[writtenSz:]

		// 6. Setup rendundant data
		if len(chunkBuffer) > 0 {
			asd.DecBuffer = chunkBuffer
		} else {
			asd.DecBuffer = nil
		}
		asd.CurrentDecBufferSize = len(asd.DecBuffer)

		// 7. Maintain state for next interation and return values
		buf = buf[writtenSz:]
		sz += writtenSz
	}

	return
}

// NewDefaultStreamEncryptor creates DefaultStreamEncryptor from encryptor and writer.
func NewDefaultStreamEncryptor(e Encryptor, w io.Writer) StreamEncryptor {
	dse := &defaultStreamEncryptor{
		Encryptor:            e,
		ChunkCounterEncoding: ByteVar,
		Sink:                 w,
		EncBuffer:            make([]byte, 1024*1024), // TODO(teaiwthsand): make this configurable
	}
	return dse
}

// NewDefaultStreamDecryptor creates DefaultStreamDecryptor from decryptor and reader.
func NewDefaultStreamDecryptor(d Decryptor, r io.Reader) StreamDecryptor {
	dsd := &defaultStreamDecryptor{
		Decryptor:            d,
		ChunkCounterEncoding: ByteVar,
		Source:               r,
		MaxBufferSize:        1024 * 1024, // TODO(teawithsand): make this configurable value
	}
	return dsd
}
