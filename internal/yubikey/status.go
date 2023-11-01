package yubikey

type statusFlags uint8

func (s statusFlags) ResponsePending() bool {
	return s&responsePendingFlag == responsePendingFlag
}

func (s statusFlags) SlotWrite() bool {
	return s&slotWriteFlag == slotWriteFlag
}

func (s statusFlags) TimeoutWait() int {
	if s&responseTimeoutWaitFlag == responseTimeoutWaitFlag {
		return int(s & responseTimeoutWaitMask)
	} else {
		return 0
	}
}
