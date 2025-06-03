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

func HandleShellCmd(modName string, data []byte, base common.BaseEvent, bootTimeOffsetNs int64) {
	var fullEvent common.ShellCmdEvent
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &fullEvent); err != nil {
		fmt.Printf("failed to parse ShellCmdEvent from %s: %v\n", modName, err)
		return
	}
	commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
	cmdStr := strings.TrimRight(string(fullEvent.Command[:]), "\x00")
	timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()

	output, _ := json.MarshalIndent(struct {
		common.JSONBaseEvent
		Command string `json:"Command"`
	}{
		JSONBaseEvent: common.JSONBaseEvent{
			EventType: fullEvent.EventType,
			PID:       fullEvent.PID,
			PPID:      fullEvent.PPID,
			UID:       fullEvent.UID,
			Comm:      commStr,
			Timestamp: timestampStr,
		},
		Command: cmdStr,
	}, "", "  ")

	fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
}

