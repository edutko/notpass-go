package yubikey

func crc16(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			j := crc & 1
			crc >>= 1
			if j != 0 {
				crc ^= 0x8408
			}
		}
	}

	return crc
}

func verifyCrc(data []byte) bool {
	return crc16(data) == crcOkResidual
}

const crcOkResidual = uint16(0xf0b8)
