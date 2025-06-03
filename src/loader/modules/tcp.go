package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hwigun/WE-MEET/common"
	"time"
)

func HandleTcpConnect(modName string, data []byte, base common.BaseEvent, bootTimeOffsetNs int64) {
	var fullEvent common.TCPConnectEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &fullEvent); err != nil {
		fmt.Printf("failed to parse TCPConnectEvent from %s: %v\n", modName, err)
		return
	}
	commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
	timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
	output, _ := json.MarshalIndent(struct {
		common.JSONBaseEvent
		Saddr    uint32 `json:"Saddr"`
		Daddr    uint32 `json:"Daddr"`
		Sport    uint16 `json:"Sport"`
		Dport    uint16 `json:"Dport"`
		Protocol uint8  `json:"Protocol"`
	}{
		JSONBaseEvent: common.JSONBaseEvent{
			EventType: fullEvent.EventType,
			PID:       fullEvent.PID,
			PPID:      fullEvent.PPID,
			UID:       fullEvent.UID,
			Comm:      commStr,
			Timestamp: timestampStr,
		},
		Saddr:    fullEvent.Saddr,
		Daddr:    fullEvent.Daddr,
		Sport:    fullEvent.Sport,
		Dport:    fullEvent.Dport,
		Protocol: fullEvent.Protocol,
	}, "", "  ")
	fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
}
