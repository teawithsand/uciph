package uciph

import "crypto/subtle"

// TODO(teawithsand): test if these functions are indeed constatnt time

type Padder interface {
	Pad(data []byte, msgSize int) []byte
}

type PadderFunc func(data []byte, msgSize int) []byte

func (f PadderFunc) Pad(data []byte, msgSize int) []byte {
	return f(data, msgSize)
}

type Unpadder interface {
	// Unpad returns value < 0 if it failed
	Unpad(data []byte) (msgSize int)
}

type UnpadderFunc func(data []byte) (msgSize int)

func (f UnpadderFunc) Unpad(data []byte) (msgSize int) {
	return f(data)
}

type Padding interface {
	Padder
	Unpadder
}

type compositePadding struct {
	Padder
	Unpadder
}

var IEC78164Padding Padding = &compositePadding{
	// Padder padds fills buf[msgSize:] with padding.
	// There always must be at least one free for padding byte in buf. Otherwise behaviour is undefined.
	Padder: PadderFunc(func(data []byte, msgSize int) []byte {
		msgSizeMinusOne := msgSize - 1
		for i := 0; i < len(data); i++ {
			res := subtle.ConstantTimeSelect(
				subtle.ConstantTimeLessOrEq(i, msgSizeMinusOne),
				int(data[i]), // is cast constant time
				subtle.ConstantTimeSelect(
					subtle.ConstantTimeEq(int32(msgSize), int32(i)),
					0x80,
					0x00,
				),
			)
			data[i] = byte(res) // is cast constant time?
		}

		return data
	}),
	// Unpadder removes SO/IEC 7816-4 in constant time
	// depending on length of message with padding, not unpadded message
	Unpadder: UnpadderFunc(func(data []byte) (msgSize int) {
		sz := len(data)
		// TODO(teawithsand): force i to be less than signed 32bit int max on 64bit platform

		isPaddingDone := 0
		for i := len(data) - 1; i >= 0; i-- {
			isPaddingDone |= subtle.ConstantTimeByteEq(data[i], 0x80)
			sz = subtle.ConstantTimeSelect(isPaddingDone, sz, sz-1)
		}

		return subtle.ConstantTimeSelect(isPaddingDone, sz-1, -1)
	}),
}
