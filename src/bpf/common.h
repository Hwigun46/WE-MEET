#include <vmlinux.h>

#ifndef __COMMON_H
#define __COMMON_H

// event 타입
enum custom_event_type_t
{
    EVENT_PROCESS_CREATE,
    EVENT_PROCESS_TERMINATE,
    EVENT_FILE_OPEN,
    EVENT_TCP_CONNECT,
    EVENT_SHELL_CMD,
    EVENT_PRIVILEGE_CHANGE,
    EVENT_BPF_LOAD
};

// 기본 구조체
struct base_event_t
{

    enum custom_event_type_t event_type;

    u32 pid;  // 프로세스 ID
    u32 ppid; // 부모 PID
    u32 uid;  /// 사용자
    char comm[16];    // 명령어
    u64 timestamp_ns; // 실행 시간
};

// 프로세스 생성 log 구조체
struct process_create_event_t
{
    struct base_event_t base;
};

// 프로세스 종료 log 구조체
struct process_terminate_event_t
{
    struct base_event_t base;
    int exit_code;   // 종료 코드
    u64 duration_ns; // 실행 시간
};

// file open(create) 구조체
struct file_open_event_t
{
    struct base_event_t base;

    char filename[256]; // 열거나 생성하려는 파일의 경로
    int flags;          // open syscall에서의 플래그  (읽기/쓰기/생성 등)
    int mode;           // 권한 (O_CREAT 시의 퍼미션 모드)
};

// tcp 연결 log 구조체
struct tcp_connect_event_t
{
    struct base_event_t base;
    u32 saddr;   // 시작 주소
    u32 daddr;   // 도착 주소
    u16 sport;   // 시작 포트
    u16 dport;   // 도착 포트
    u8 protocol; // 프로토콜
};

// map에 들어갈 sock 정보
struct sock_info_t
{
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// shell command log 구조체
struct shell_cmd_event_t
{
    struct base_event_t base;
    char command[256]; // Full command line
};

// map에 들어갈 기존 uid 정보
struct euid_info_t
{
    u32 pid;
    u32 old_uid;
    u32 old_euid;
};

// 권한 변경 log 구조체
struct privilege_change_event_t
{
    struct base_event_t base;
    u32 old_uid;
    u32 old_euid;
    u32 new_euid;
};

#endif