package yubikey

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/google/gousb"
)

func (y *usbHidYubiKey) Close() error {
	var err1, err2 error

	err1 = y.dev.Close()
	if y.ctx != nil {
		err2 = y.ctx.Close()
	}

	if err1 != nil {
		return err1
	}
	return err2
}

func (y *usbHidYubiKey) ChallengeResponseHmacSha1(slot int, challenge []byte) ([]byte, error) {
	if len(challenge) > slotDataSize {
		return nil, fmt.Errorf("invalid challenge (expected maximum of %d bytes)", slotDataSize)
	}

	f := frame{payload: challenge, slot: slotChalRespHmacSlot1}
	if slot == 2 {
		f.slot = slotChalRespHmacSlot2
	}

	data, err := y.writeAndRead(f, sha1.Size)
	if err != nil {
		return nil, fmt.Errorf("writeAndRead: %w", err)
	}

	return data, nil
}

func (y *usbHidYubiKey) Serial() (string, error) {
	f := frame{slot: slotDeviceSerial}
	data, err := y.writeAndRead(f, 4)
	if err != nil {
		return "", fmt.Errorf("writeAndRead: %w", err)
	}

	serial := int(binary.BigEndian.Uint32(data[:4]))

	return strconv.Itoa(serial), nil
}

func (y *usbHidYubiKey) Type() (string, error) {
	return y.dev.Product()
}

func (y *usbHidYubiKey) Version() (string, error) {
	err := y.reset()
	if err != nil {
		return "", fmt.Errorf("reset: %w", err)
	}

	data, _, err := y.readFeatureReport()
	if err != nil {
		return "", fmt.Errorf("readFeatureReport: %w", err)
	}

	return fmt.Sprintf("%d.%d.%d", data[1], data[2], data[3]), nil
}

func findYubikeys(ctx *gousb.Context) ([]*usbHidYubiKey, error) {
	devs, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		return desc.Vendor == yubicoVid
	})

	if err != nil {
		for _, d := range devs {
			_ = d.Close()
		}
		return nil, fmt.Errorf("ctx.OpenDevices: %w", err)
	}

	yks := make([]*usbHidYubiKey, len(devs))
	for i, d := range devs {
		yks[i] = &usbHidYubiKey{dev: d}
	}

	return yks, nil
}

func (y *usbHidYubiKey) info() (Info, error) {
	s, err := y.Serial()
	if err != nil {
		return Info{}, fmt.Errorf("y.Serial: %w", err)
	}
	t, err := y.Type()
	if err != nil {
		return Info{}, fmt.Errorf("y.Type: %w", err)
	}
	v, err := y.Version()
	if err != nil {
		return Info{}, fmt.Errorf("y.Version: %w", err)
	}

	return Info{
		Serial:  s,
		Type:    t,
		Version: v,
	}, nil
}

func (y *usbHidYubiKey) waitUntilReadyForSlotWrite() ([]byte, error) {
	return y.waitForStatus(func(status statusFlags) bool {
		return !status.SlotWrite()
	})
}

func (y *usbHidYubiKey) waitUntilResponseIsPending() ([]byte, error) {
	return y.waitForStatus(func(status statusFlags) bool {
		return status.ResponsePending()
	})
}

func (y *usbHidYubiKey) waitForStatus(check func(status statusFlags) bool) ([]byte, error) {
	maxDelay := 20 * time.Second
	perLoopDelay := 500 * time.Millisecond
	time.Sleep(10 * time.Millisecond)
	for remaining := maxDelay; remaining > 0; remaining -= perLoopDelay {
		data, status, err := y.readFeatureReport()
		if err != nil {
			return nil, err
		}

		wait := status.TimeoutWait()
		if wait > 0 {
			remaining = time.Duration(wait)*time.Second - perLoopDelay
		}

		if check(status) {
			return data, nil
		}
		time.Sleep(perLoopDelay)
	}
	return nil, fmt.Errorf("timed out")
}

func (y *usbHidYubiKey) writeAndRead(f frame, responseLen int) ([]byte, error) {
	err := y.reset()
	if err != nil {
		return nil, fmt.Errorf("reset: %w", err)
	}

	_, err = y.waitUntilReadyForSlotWrite()
	if err != nil {
		return nil, fmt.Errorf("waitUntilReadyForSlotWrite: %w", err)
	}

	err = y.writeFrame(f)
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	prefix, err := y.waitUntilResponseIsPending()
	if err != nil {
		return nil, fmt.Errorf("waitUntilResponseIsPending: %w", err)
	}

	data, err := y.readFrame()
	if err != nil {
		_ = y.reset()
		return nil, err
	}

	data = append(prefix, data...)
	if !verifyCrc(data[:responseLen+2]) {
		return nil, fmt.Errorf("invalid checksum on response")
	}

	return data[:responseLen], nil
}

func (y *usbHidYubiKey) readFrame() ([]byte, error) {
	data := make([]byte, 0)
	for {
		resp, status, err := y.readFeatureReport()
		if err != nil {
			return nil, fmt.Errorf("readFeatureReport: %w", err)
		}
		if status.ResponsePending() {
			if status&responseTimeoutWaitMask == 0 {
				return data, nil
			}
			data = append(data, resp...)
		} else {
			data = append(data, resp...)
			return data, nil
		}
	}
}

func (y *usbHidYubiKey) readFeatureReport() ([]byte, statusFlags, error) {
	fr := make([]byte, featureReportSize)
	_, err := y.dev.Control(usbTypeClass|usbRecipInterface|usbEndpointIn, hidGetReport, reportTypeFeature<<8, 0, fr)
	return fr[:featureReportSize-1], statusFlags(fr[featureReportSize-1]), err
}

func (y *usbHidYubiKey) reset() error {
	return y.writeFeatureReport([8]byte{0, 0, 0, 0, 0, 0, 0, slotDummyReport})
}

func (y *usbHidYubiKey) writeFrame(f frame) error {
	data := f.toBytes()
	seq := byte(0)
	count := byte((len(data) + 6) / 7)

	for i := 0; i < len(data); i += featureReportSize - 1 {
		_, err := y.waitUntilReadyForSlotWrite()
		if err != nil {
			return err
		}

		var fr [featureReportSize]byte
		copy(fr[:], data[i:i+featureReportSize-1])

		// skip any all-zero buffers in the middle
		if seq == 0 || seq == count-1 || !bytes.Equal(fr[:], []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
			fr[featureReportSize-1] = slotWriteFlag + seq
			err = y.writeFeatureReport(fr)
			if err != nil {
				return err
			}
		}
		seq += 1
	}

	return nil
}

func (y *usbHidYubiKey) writeFeatureReport(fr [featureReportSize]byte) error {
	_, err := y.dev.Control(usbTypeClass|usbRecipInterface|usbEndpointOut, hidSetReport, reportTypeFeature<<8, 0, fr[:])
	return err
}

type usbHidYubiKey struct {
	ctx *gousb.Context
	dev *gousb.Device
}

const yubicoVid = 0x1050

const (
	usbTypeClass      uint8 = 0x01 << 5
	usbRecipInterface uint8 = 0x01
	usbEndpointIn     uint8 = 0x80
	usbEndpointOut    uint8 = 0x00

	hidGetReport uint8 = 0x01
	hidSetReport uint8 = 0x09
)

const (
	reportTypeFeature uint16 = 0x03

	featureReportSize = 8
	slotDataSize      = 64
)

const (
	responseTimeoutWaitMask = 0x1f
	responseTimeoutWaitFlag = 0x20
	responsePendingFlag     = 0x40
	slotWriteFlag           = 0x80
)

const (
	slotDeviceSerial      byte = 0x10
	slotChalRespHmacSlot1 byte = 0x30
	slotChalRespHmacSlot2 byte = 0x38
	slotDummyReport       byte = 0x8f
)
