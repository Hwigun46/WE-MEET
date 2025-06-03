package common

// 기본 이벤트
type BaseEvent struct {
	EventType   uint32
	PID         uint32
	PPID        uint32
	UID         uint32
	Comm        [16]byte
	TimestampNs uint64
}

// process create 이벤트
type ProcessCreateEvent struct {
	BaseEvent
}

// process terminate 이벤트
type ProcessTerminateEvent struct {
	BaseEvent
	ExitCode int32
}

// file open(create) 이벤트
type FileOpenEvent struct {
	BaseEvent
	Filename [256]byte
	Flags    int32
	Mode     int32
}

// tcp connect 이벤트
type TCPConnectEvent struct {
	BaseEvent
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8
}

// shell command 이벤트
type ShellCmdEvent struct {
	BaseEvent
	Command [128]byte
}

type PrivilegeChangeEvent struct {
	BaseEvent
	OldUID  uint32
	OldEUID uint32
	NewEUID uint32
}

// json 출력용 base struct
type JSONBaseEvent struct {
	EventType uint32 `json:"EventType"`
	PID       uint32 `json:"PID"`
	PPID      uint32 `json:"PPID"`
	UID       uint32 `json:"UID"`
	Comm      string `json:"Comm"`
	Timestamp string `json:"Timestamp"`
}