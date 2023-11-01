package yubikey

type frame struct {
	payload []byte
	slot    uint8
}

func (f *frame) toBytes() []byte {
	if len(f.payload) < slotDataSize {
		padding := make([]byte, slotDataSize-len(f.payload))
		f.payload = append(f.payload, padding...)
	}
	crc := crc16(f.payload)

	b := f.payload
	b = append(b, f.slot)
	b = append(b, byte(crc&0xff))
	b = append(b, byte((crc>>8)&0xff))

	return b
}
