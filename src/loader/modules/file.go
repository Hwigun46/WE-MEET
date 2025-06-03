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

func HandleFileOpen(modName string, data []byte, base common.BaseEvent, bootTimeOffsetNs int64){
	var fullEvent common.FileOpenEvent
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &fullEvent); err != nil {
				fmt.Printf("failed to parse FileOpenEvent from %s: %v\n", modName, err)
				return
			}
			commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
			timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
			filenameStr := strings.TrimRight(string(fullEvent.Filename[:]), "\x00")
			output, _ := json.MarshalIndent(struct {
				common.JSONBaseEvent
				Filename string `json:"Filename"`
				Flags    int32  `json:"Flags"`
				Mode     int32  `json:"Mode"`
			}{
				JSONBaseEvent: common.JSONBaseEvent{
					EventType: fullEvent.EventType,
					PID:       fullEvent.PID,
					PPID:      fullEvent.PPID,
					UID:       fullEvent.UID,
					Comm:      commStr,
					Timestamp: timestampStr,
				},
				Filename: filenameStr,
				Flags:    fullEvent.Flags,
				Mode:     fullEvent.Mode,
			}, "", "  ")
			fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
}