package pad

import "crypto/subtle"

// TODO(teawithsand): make these interfaces functions, since using them as interfaces is quite pointless and
//  leads to less readable code
// TODO(teawithsand): test if these functions are indeed constatnt time

// Padder is something able to apply padding to message.
type Padder interface {
	Pad(data []byte, msgSize int) []byte
}

// PadderFunc is function which is Padder.
type PadderFunc func(data []byte, msgSize int) []byte

// Pad makes PadderFunc satisfy Padder.
func (f PadderFunc) Pad(data []byte, msgSize int) []byte {
	return f(data, msgSize)
}

// Unpadder is something able to remove padding.
type Unpadder interface {
	// Unpad returns value < 0 if it failed
	Unpad(data []byte) (msgSize int)
}

// UnpadderFunc if cuntion which is Unpadder.
type UnpadderFunc func(data []byte) (msgSize int)

// Unpad makes UnpadderFunc satisfy Unpadder.
func (f UnpadderFunc) Unpad(data []byte) (msgSize int) {
	return f(data)
}

// Padding is something, which gets messsage
// and makes it constant length.
// It's also able to reverse it.
type Padding interface {
	Padder
	Unpadder
}

// util, which simplifes creating paddings.
type compositePadding struct {
	Padder
	Unpadder
}

// TOOD(teawihtsand): debug why this is not constant time
// at least looks like so, when benchmark are in use

// write these in asm?

var iec78164Padding Padding = &compositePadding{
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

// IEC78164Padding is single padding scheme, which has simple format:
// [any, any, any..., 0x80, 0x00, 0x00, 0x00...].
func IEC78164Padding() Padding {
	return iec78164Padding
}
