package main

import (
    "github.com/hwigun/WE-MEET/config"
    "github.com/hwigun/WE-MEET/loader"
    "os"
    "os/signal"
    "syscall"
    "log"
)

func main() {
    // (1) modules.yml 읽기
    modules, err := config.LoadConfig("config/modules.yml")
    if err != nil {
        log.Fatalf("failed to load config: %v", err)
    }

    // (2) loader 초기화
    ul := loader.NewUnifiedLoaderFromConfig(modules)

    // (3) 고루틴 실행
    go ul.Run()

    // (4) 종료 신호 대기
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig
    log.Println("Shutting down...")
}