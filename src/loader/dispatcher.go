package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/hwigun/WE-MEET/common"
	"github.com/hwigun/WE-MEET/loader/modules"
)

func Dispatch(modName string, rdr *ringbuf.Reader, bootTimeOffsetNs *int64, once *sync.Once) {
	for {
		record, err := rdr.Read()
		if err != nil {
			continue
		}

		// 먼저 BaseEvent만 읽어서 event_type을 확인
		var base common.BaseEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &base); err != nil {
			fmt.Printf("failed to parse base event from %s: %v\n", modName, err)
			continue
		}
		once.Do(func() {
			*bootTimeOffsetNs = time.Now().UnixNano() - int64(base.TimestampNs)
		})

		switch base.EventType {
		case 0: // EVENT_PROCESS_CREATE
			modules.HandleProcessCreate(modName, record.RawSample, base, *bootTimeOffsetNs)

		case 1: // EVENT_PROCESS_TERMINATE
			modules.HandleProcessTerminate(modName, record.RawSample, base, *bootTimeOffsetNs)

		case 2: // EVENT_FILE_OPEN
			modules.HandleFileOpen(modName, record.RawSample, base, *bootTimeOffsetNs)
		case 3: // EVENT_TCP_CONNECT
			modules.HandleTcpConnect(modName, record.RawSample, base, *bootTimeOffsetNs)
		case 4: // EVENT_SHELL_CMD
			modules.HandleShellCmd(modName, record.RawSample, base, *bootTimeOffsetNs)

		// case 5: // EVENT_PRIVILEGE_CHANGE
		// 	var fullEvent PrivilegeChangeEvent
		// 	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
		// 		fmt.Printf("failed to parse PrivilegeChangeEvent from %s: %v\n", modName, err)
		// 		continue
		// 	}
		// 	commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
		// 	timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+*bootTimeOffsetNs).Local().String()
		// 	output, _ := json.MarshalIndent(struct {
		// 		JSONBaseEvent
		// 		OldUID  uint32 `json:"OldUID"`
		// 		OldEUID uint32 `json:"OldEUID"`
		// 		NewEUID uint32 `json:"NewEUID"`
		// 	}{
		// 		JSONBaseEvent: JSONBaseEvent{
		// 			EventType: fullEvent.EventType,
		// 			PID:       fullEvent.PID,
		// 			PPID:      fullEvent.PPID,
		// 			UID:       fullEvent.UID,
		// 			Comm:      commStr,
		// 			Timestamp: timestampStr,
		// 		},
		// 		OldUID:  fullEvent.OldUID,
		// 		OldEUID: fullEvent.OldEUID,
		// 		NewEUID: fullEvent.NewEUID,
		// 	}, "", "  ")
		// 	fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
		default:
			fmt.Printf("[%s] Unknown event type: %d\n", modName, base.EventType)
		}
	}
}
