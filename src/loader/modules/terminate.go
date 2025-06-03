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

func HandleProcessTerminate(modName string, data []byte, base common.BaseEvent, bootTimeOffsetNs int64) {
	var fullEvent common.ProcessTerminateEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &fullEvent); err != nil {
		fmt.Printf("failed to parse ProcessTerminateEvent from %s: %v\n", modName, err)
		return
	}
	commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
	timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
	output, _ := json.MarshalIndent(struct {
		common.JSONBaseEvent
		ExitCode   int32  `json:"ExitCode"`
		DurationNs uint64 `json:"DurationNs"`
	}{
		JSONBaseEvent: common.JSONBaseEvent{
			EventType: fullEvent.EventType,
			PID:       fullEvent.PID,
			PPID:      fullEvent.PPID,
			UID:       fullEvent.UID,
			Comm:      commStr,
			Timestamp: timestampStr,
		},
		ExitCode: fullEvent.ExitCode,
	}, "", "  ")
	fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
}
