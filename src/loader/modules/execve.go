package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	
	"time"
	"github.com/hwigun/WE-MEET/common"

)

func HandleProcessCreate(modName string, data []byte, base common.BaseEvent, bootTimeOffsetNs int64){
	var fullEvent common.ProcessCreateEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &fullEvent); err != nil {
		fmt.Printf("failed to parse ProcessCreateEvent from %s: %v\n", modName, err)
		return
	}
	commStr := strings.TrimRight(string(base.Comm[:]), "\x00")
	timestampStr := time.Unix(0, int64(base.TimestampNs)+bootTimeOffsetNs).Local().String()
	output, _ := json.MarshalIndent(struct {
		common.JSONBaseEvent
		StartTimeNs uint64 `json:"StartTimeNs"`
	}{
		JSONBaseEvent: common.JSONBaseEvent{
			EventType: fullEvent.EventType,
			PID:       fullEvent.PID,
			PPID:      fullEvent.PPID,
			UID:       fullEvent.UID,
			Comm:      commStr,
			Timestamp: timestampStr,
		},
	}, "", "  ")
	fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
}