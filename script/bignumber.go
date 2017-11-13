package script

import "fmt"

// BigNumber represents the scriptnum in bitcoin.
type BigNumber int64

const (
	defaultMaxNumSize = 4
)

// BytesToBigNumber decodes bytes to uint64.
func BytesToBigNumber(d []byte, isRequireMinimal bool, maxNumberSize int) (BigNumber, error) {
	if len(d) > maxNumberSize {
		return 0, fmt.Errorf("script number overflow")
	}
	if isRequireMinimal && len(d) > 0 {
		// Check that the number is encoded with the minimum possible
		// number of bytes.
		//
		// If the most-significant-byte - excluding the sign bit - is zero
		// then we're not minimal. Note how this test also rejects the
		// negative-zero encoding, 0x80.
		if (d[len(d)-1] & 0x7f) == 0 {
			// One exception: if there's more than one byte and the most
			// significant bit of the second-most-significant-byte is set
			// it would conflict with the sign bit. An example of this case
			// is +-255, which encode to 0xff00 and 0xff80 respectively.
			// (big-endian).
			if len(d) <= 1 || (d[len(d)-2]&0x80) == 0 {
				return 0, fmt.Errorf("non-minimally encoded script number")
			}
		}
	}

	var bn BigNumber
	for i := 1; i != len(d); i++ {
		bn |= (BigNumber)(d[i]) << uint8(8*i)
	}

	// If the input vector's most significant byte is 0x80, remove it from
	// the result's msb and return a negative.
	if (d[len(d)-1] & 0x80) != 0 {
		return -(bn & ^(0x80 << uint8(8*(len(d)-1)))), nil
	}
	return bn, nil

}

// Bytes encodes int64 to bytes.
func (bn BigNumber) Bytes() []byte {
	n := int64(bn)
	if n == 0 {
		return nil
	}

	var (
		result   []byte
		isNeg    bool
		absValue int64
	)

	if isNeg = n < 0; isNeg {
		absValue = -n
	}
	absValue = n

	for absValue > 0 {
		result = append(result, byte(absValue&0xff))
		absValue >>= 8
	}

	//    - If the most significant byte is >= 0x80 and the value is positive, push a
	//    new zero-byte to make the significant byte < 0x80 again.

	//    - If the most significant byte is >= 0x80 and the value is negative, push a
	//    new 0x80 byte that will be popped off when converting to an integral.

	//    - If the most significant byte is < 0x80 and the value is negative, add
	//    0x80 to it, since it will be subtracted and interpreted as a negative when
	//    converting to an integral.
	if result[len(result)-1]&0x80 != 0 {
		if isNeg {
			result = append(result, 0x80)
		} else {
			result = append(result, 0)
		}
	}
	if isNeg {
		result[len(result)-1] |= 0x80
	}

	return result
}
