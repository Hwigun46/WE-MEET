package loader

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/hwigun/WE-MEET/config"
)

// 어디에 attach 할지 확인하기
type AttachInfo struct {
	Function string
	Type     string
	Binary   string
}

// .bpf.o 파일 형태
type BPFModule struct {
	Path     string
	Programs map[string]AttachInfo
	Mapname  string
}

type Loader interface {
	Run() error
	Close() error
}

type UnifiedLoader struct {
	modules []BPFModule
	readers []*ringbuf.Reader
	links   []link.Link
}

func (l *UnifiedLoader) Run() error {

	// 메모리 제한 안두기
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 부팅 시점 기록
	var bootTimeOffsetNs int64
	var once sync.Once

	// index는 사용 안해서 _ 처리 , mod에 modules 값 하나씩 반환
	for _, mod := range l.modules {

		//
		if _, err := os.Stat(mod.Path); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "skipping %s: file does not exist\n", mod.Path)
			continue
		}

		// LoadCollectionSpec이 spec과 err를 반환
		// spec은 .bpf.o 파일에 정의된 프로그램과 맵 등 메타데이터
		// err가 nil이 아니면 err 처리
		spec, err := ebpf.LoadCollectionSpec(mod.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load BPF spec from %s: %v\n", mod.Path, err)
			continue
		}

		// NewCollection이 coll과 err를 반환
		// coll은 로딩된 BPF 프로그램들과 맵들을 담고 있는 Collection 객체
		// err가 nil이 아니면 err 처리
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load BPF collection from %s: %v\n", mod.Path, err)
			continue
		}

		for progName, attach := range mod.Programs {
			prog := coll.Programs[progName]

			// prog는 nil이면 null과 비슷한거
			// 문제가 있다는 뜻
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

			case "uretprobe":
				if attach.Binary == "" {
					fmt.Fprintf(os.Stderr, "missing binary path for %s: %s\n", attach.Type, progName)
					continue
				}
				if attach.Function == "" {
					fmt.Fprintf(os.Stderr, "missing symbol name for %s: %s\n", attach.Type, progName)
					continue
				}
				exe, openErr := link.OpenExecutable(attach.Binary)
				if openErr != nil {
					fmt.Fprintf(os.Stderr, "failed to open binary %s: %v\n", attach.Binary, openErr)
					continue
				}
				lnk, err = exe.Uretprobe(attach.Function, prog, nil)

			default:
				fmt.Fprintf(os.Stderr, "unsupported attach type %s for %s\n", attach.Type, progName)
				continue
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to attach %s to %s: %v\n", progName, attach.Function, err)
				continue
			}
			l.links = append(l.links, lnk)
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
		l.readers = append(l.readers, reader)

		go Dispatch(mod.Path, reader, &bootTimeOffsetNs, &once)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig // 여기서 대기하다가 Ctrl+C 입력 시 아래로 진행
	fmt.Println("exiting")

	return nil
}

func (l *UnifiedLoader) Close() error {
	var err error
	for _, rdr := range l.readers {
		if closeErr := rdr.Close(); closeErr != nil {
			err = closeErr
		}
	}
	for _, lnk := range l.links {
		if closeErr := lnk.Close(); closeErr != nil {
			err = closeErr
		}
	}
	return err
}

func NewUnifiedLoaderFromConfig(c *config.Config) *UnifiedLoader {
	modules := make([]BPFModule, 0, len(c.Modules))

	for _, m := range c.Modules {
		modules = append(modules, BPFModule{
			Path:    m.Path,
			Mapname: m.Mapname,
			Programs: func() map[string]AttachInfo {
				progMap := make(map[string]AttachInfo)
				for name, info := range m.Programs {
					progMap[name] = AttachInfo{
						Function: info.Function,
						Type:     info.Type,
						Binary:   info.Binary,
					}
				}
				return progMap
			}(),
		})
	}

	return &UnifiedLoader{
		modules: modules,
	}
}