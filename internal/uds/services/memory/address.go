package memory

import "github.com/adpego/godocan/internal/uds"

// Address is a decoded memoryAddress/memorySize pair.
type Address struct {
	Addr uint32
	Size uint32
	Len  int // bytes used by addressAndLengthFormatIdentifier, address and size
}

// ParseAddress decodes addressAndLengthFormatIdentifier followed by
// memoryAddress and memorySize (ISO 14229-1, 7.5.10). It returns an NRC on
// failure: 0x31 for unsupported field sizes, 0x13 if data is too short.
func ParseAddress(data []byte) (Address, byte) {
	if len(data) < 1 {
		return Address{}, uds.NRCInvalidMessageLengthOrFormat
	}
	sizeLen, addrLen := int(data[0]>>4), int(data[0]&0x0F)
	if addrLen == 0 || sizeLen == 0 || addrLen > 4 || sizeLen > 4 {
		return Address{}, uds.NRCRequestOutOfRange
	}
	n := 1 + addrLen + sizeLen
	if len(data) < n {
		return Address{}, uds.NRCInvalidMessageLengthOrFormat
	}
	return Address{
		Addr: beUint(data[1 : 1+addrLen]),
		Size: beUint(data[1+addrLen : n]),
		Len:  n,
	}, 0
}

func beUint(b []byte) uint32 {
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32(x)
	}
	return v
}
