package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event struct definitions matching the C structs in common.h
type BaseEvent struct {
	EventType   uint32
	PID         uint32
	TID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	Comm        [16]byte
	TimestampNs uint64
}

type ProcessCreateEvent struct {
	BaseEvent
	StartTimeNs uint64
}

type ProcessTerminateEvent struct {
	BaseEvent
	ExitCode   int32
	DurationNs uint64
}

type FileOpenEvent struct {
	BaseEvent
	Filename [256]byte
	Flags    int32
	Mode     int32
}

type TCPConnectEvent struct {
	BaseEvent
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8
}

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

// 어디에 attach 할지 확인하기
type AttachInfo struct {
	Function string
	Type     string
}

// .bpf.o 파일 형태
type BPFModule struct {
	Path     string
	Programs map[string]AttachInfo
	Mapname  string
}

// json 출력용 base struct
type JSONBaseEvent struct {
	EventType uint32 `json:"EventType"`
	PID       uint32 `json:"PID"`
	TID       uint32 `json:"TID"`
	PPID      uint32 `json:"PPID"`
	UID       uint32 `json:"UID"`
	GID       uint32 `json:"GID"`
	Comm      string `json:"Comm"`
	Timestamp string `json:"Timestamp"`
}

func main() {

	// 메모리 제한 안두기
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(fmt.Sprintf("failed to remove memlock: %v", err))
	}

	var bootTimeOffsetNs int64
	var once sync.Once

	modules := []BPFModule{

		{
			Path: "build/process_create.bpf.o",
			Programs: map[string]AttachInfo{
				"handle_process_create": {
					Function: "syscalls:sys_enter_execve",
					Type:     "tracepoint",
				},
			},
			Mapname: "process_create_event_map",
		},

		{
			Path: "build/process_terminate.bpf.o",
			Programs: map[string]AttachInfo{
				"handle_process_terminate": {
					Function: "do_exit",
					Type:     "kprobe",
				},
			},
			Mapname: "process_terminate_event_map",
		},

		{
			Path: "build/file_open.bpf.o",
			Programs: map[string]AttachInfo{
				"handle_file_open": {
					Function: "syscalls:sys_enter_openat",
					Type:     "tracepoint",
				},
			},
			Mapname: "file_open_event_map",
		},

		{
			Path: "build/tcp_connect.bpf.o",
			Programs: map[string]AttachInfo{
				"handle_tcp_connect_kprobe": {
					Function: "tcp_connect",
					Type:     "kprobe",
				},
				"handle_tcp_connect_kretprobe": {
					Function: "tcp_connect",
					Type:     "kretprobe",
				},
			},
			Mapname: "tcp_connect_event_map",
		},

		{
			Path: "build/shell_cmd.bpf.o",
			Programs: map[string]AttachInfo{
				"handle_shell_cmd": {
					Function: "sys_execve",
					Type:     "kprobe",
				},
			},
			Mapname: "shell_cmd_event_map",
		},

		{
			Path: "build/privilege_change.bpf.o",
			Programs: map[string]AttachInfo{
				"handle_privilege_change_kprobe": {
					Function: "sys_setreuid",
					Type:     "kprobe",
				},

				"handle_privilege_change_kretprobe": {
					Function: "sys_setreuid",
					Type:     "kretprobe",
				},
			},
			Mapname: "privilege_change_event_map",
		},
	}

	for _, mod := range modules {

		if _, err := os.Stat(mod.Path); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "skipping %s: file dose not exist\n", mod.Path)
			continue
		}

		spec, err := ebpf.LoadCollectionSpec(mod.Path)

		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load BPF spec from %s: %v\n", mod.Path, err)
			continue
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load BPF collection from %s: %v\n", mod.Path, err)
			continue
		}

		for progName, attach := range mod.Programs {
			prog := coll.Programs[progName]

			if prog == nil {
				fmt.Fprintf(os.Stderr, "program %s not found in %s\n", progName, mod.Path)
				continue
			}

			var lnk link.Link
			switch attach.Type {
			case "tracepoint":
				parts := strings.Split(attach.Function, ":")
				if len(parts) != 2 {
					fmt.Fprintf(os.Stderr, "invalid tracepoint format: %s\n", attach.Function)
					continue
				}
				category := parts[0]
				name := parts[1]
				lnk, err = link.Tracepoint(category, name, prog, nil)

			case "kprobe":
				lnk, err = link.Kprobe(attach.Function, prog, nil)

			case "kretprobe":
				lnk, err = link.Kretprobe(attach.Function, prog, nil)

			default:
				fmt.Fprintf(os.Stderr, "unsupported attach type %s for %s\n", attach.Type, progName)
				continue
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to attach %s to %s: %v\n", progName, attach.Function, err)
				continue
			}
			defer lnk.Close()
		}

		eventMap := coll.Maps[mod.Mapname]
		if eventMap == nil {
			fmt.Fprintf(os.Stderr, "map %s not found in %s\n", mod.Mapname, mod.Path)
			continue
		}

		fmt.Printf("successfully loaded map %s from %s\n", mod.Mapname, mod.Path)

		reader, err := ringbuf.NewReader(eventMap)

		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create perf reader for %s: %v\n", mod.Path, err)
			continue
		}
		defer reader.Close()

		go func(modName string, rdr *ringbuf.Reader) {
			for {
				record, err := rdr.Read()
				if err != nil {
					continue
				}

				// 먼저 BaseEvent만 읽어서 event_type을 확인
				var base BaseEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &base); err != nil {
					fmt.Printf("failed to parse base event from %s: %v\n", modName, err)
					continue
				}
				once.Do(func() {
					bootTimeOffsetNs = time.Now().UnixNano() - int64(base.TimestampNs)
				})

				switch base.EventType {
				case 0: // EVENT_PROCESS_CREATE
					var fullEvent ProcessCreateEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
						fmt.Printf("failed to parse ProcessCreateEvent from %s: %v\n", modName, err)
						continue
					}
					commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
					timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
					output, _ := json.MarshalIndent(struct {
						JSONBaseEvent
						StartTimeNs uint64 `json:"StartTimeNs"`
					}{
						JSONBaseEvent: JSONBaseEvent{
							EventType: fullEvent.EventType,
							PID:       fullEvent.PID,
							TID:       fullEvent.TID,
							PPID:      fullEvent.PPID,
							UID:       fullEvent.UID,
							GID:       fullEvent.GID,
							Comm:      commStr,
							Timestamp: timestampStr,
						},
						StartTimeNs: fullEvent.StartTimeNs,
					}, "", "  ")
					fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
				case 1: // EVENT_PROCESS_TERMINATE
					var fullEvent ProcessTerminateEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
						fmt.Printf("failed to parse ProcessTerminateEvent from %s: %v\n", modName, err)
						continue
					}
					commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
					timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
					output, _ := json.MarshalIndent(struct {
						JSONBaseEvent
						ExitCode   int32  `json:"ExitCode"`
						DurationNs uint64 `json:"DurationNs"`
					}{
						JSONBaseEvent: JSONBaseEvent{
							EventType: fullEvent.EventType,
							PID:       fullEvent.PID,
							TID:       fullEvent.TID,
							PPID:      fullEvent.PPID,
							UID:       fullEvent.UID,
							GID:       fullEvent.GID,
							Comm:      commStr,
							Timestamp: timestampStr,
						},
						ExitCode:   fullEvent.ExitCode,
						DurationNs: fullEvent.DurationNs,
					}, "", "  ")
					fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
				case 2: // EVENT_FILE_OPEN
					var fullEvent FileOpenEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
						fmt.Printf("failed to parse FileOpenEvent from %s: %v\n", modName, err)
						continue
					}
					commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
					timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
					filenameStr := strings.TrimRight(string(fullEvent.Filename[:]), "\x00")
					output, _ := json.MarshalIndent(struct {
						JSONBaseEvent
						Filename string `json:"Filename"`
						Flags    int32  `json:"Flags"`
						Mode     int32  `json:"Mode"`
					}{
						JSONBaseEvent: JSONBaseEvent{
							EventType: fullEvent.EventType,
							PID:       fullEvent.PID,
							TID:       fullEvent.TID,
							PPID:      fullEvent.PPID,
							UID:       fullEvent.UID,
							GID:       fullEvent.GID,
							Comm:      commStr,
							Timestamp: timestampStr,
						},
						Filename: filenameStr,
						Flags:    fullEvent.Flags,
						Mode:     fullEvent.Mode,
					}, "", "  ")
					fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
				case 3: // EVENT_TCP_CONNECT
					var fullEvent TCPConnectEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
						fmt.Printf("failed to parse TCPConnectEvent from %s: %v\n", modName, err)
						continue
					}
					commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
					timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
					output, _ := json.MarshalIndent(struct {
						JSONBaseEvent
						Saddr    uint32 `json:"Saddr"`
						Daddr    uint32 `json:"Daddr"`
						Sport    uint16 `json:"Sport"`
						Dport    uint16 `json:"Dport"`
						Protocol uint8  `json:"Protocol"`
					}{
						JSONBaseEvent: JSONBaseEvent{
							EventType: fullEvent.EventType,
							PID:       fullEvent.PID,
							TID:       fullEvent.TID,
							PPID:      fullEvent.PPID,
							UID:       fullEvent.UID,
							GID:       fullEvent.GID,
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
				case 4: // EVENT_SHELL_CMD
					var fullEvent ShellCmdEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
						fmt.Printf("failed to parse ShellCmdEvent from %s: %v\n", modName, err)
						continue
					}
					commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
					timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
					commandStr := strings.TrimRight(string(fullEvent.Command[:]), "\x00")
					output, _ := json.MarshalIndent(struct {
						JSONBaseEvent
						Command string `json:"Command"`
					}{
						JSONBaseEvent: JSONBaseEvent{
							EventType: fullEvent.EventType,
							PID:       fullEvent.PID,
							TID:       fullEvent.TID,
							PPID:      fullEvent.PPID,
							UID:       fullEvent.UID,
							GID:       fullEvent.GID,
							Comm:      commStr,
							Timestamp: timestampStr,
						},
						Command: commandStr,
					}, "", "  ")
					fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
				case 5: // EVENT_PRIVILEGE_CHANGE
					var fullEvent PrivilegeChangeEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fullEvent); err != nil {
						fmt.Printf("failed to parse PrivilegeChangeEvent from %s: %v\n", modName, err)
						continue
					}
					commStr := strings.TrimRight(string(fullEvent.Comm[:]), "\x00")
					timestampStr := time.Unix(0, int64(fullEvent.TimestampNs)+bootTimeOffsetNs).Local().String()
					output, _ := json.MarshalIndent(struct {
						JSONBaseEvent
						OldUID  uint32 `json:"OldUID"`
						OldEUID uint32 `json:"OldEUID"`
						NewEUID uint32 `json:"NewEUID"`
					}{
						JSONBaseEvent: JSONBaseEvent{
							EventType: fullEvent.EventType,
							PID:       fullEvent.PID,
							TID:       fullEvent.TID,
							PPID:      fullEvent.PPID,
							UID:       fullEvent.UID,
							GID:       fullEvent.GID,
							Comm:      commStr,
							Timestamp: timestampStr,
						},
						OldUID:  fullEvent.OldUID,
						OldEUID: fullEvent.OldEUID,
						NewEUID: fullEvent.NewEUID,
					}, "", "  ")
					fmt.Printf("[%s] EVENT JSON: %s\n", modName, output)
				default:
					fmt.Printf("[%s] Unknown event type: %d\n", modName, base.EventType)
				}
			}
		}(mod.Path, reader)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig // 여기서 대기하다가 Ctrl+C 입력 시 아래로 진행
	fmt.Println("exiting")

}
