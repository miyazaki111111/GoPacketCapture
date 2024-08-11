package main

import (
    "fmt"
    "log"
    "net/http"
    "sync"
    "github.com/gorilla/websocket"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    // "time"
)

var (
    capturing       bool
    captureStopChan chan bool
    mu              sync.Mutex
    upgrader        = websocket.Upgrader{}
    wsConn          *websocket.Conn
    captureWG       sync.WaitGroup
)

func main() {
    // 静的ファイルの配信を設定
    fs := http.FileServer(http.Dir("./static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))

    // キャプチャ制御用のハンドラ
    http.HandleFunc("/start-capture", startCaptureHandler)
    http.HandleFunc("/stop-capture", stopCaptureHandler)

    // WebSocketハンドラ
    http.HandleFunc("/ws", wsHandler)

    // ルートハンドラでHTMLファイルを提供
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "index.html")
    })

    log.Println("Server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func startCaptureHandler(w http.ResponseWriter, r *http.Request) {
    mu.Lock()
    if capturing {
        mu.Unlock()
        fmt.Fprintln(w, "Already capturing")
        return
    }

    capturing = true
    mu.Unlock()

    captureStopChan = make(chan bool)
    captureWG.Add(1)
    go capturePackets()

    fmt.Fprintln(w, "Capture started")
}

func stopCaptureHandler(w http.ResponseWriter, r *http.Request) {
    mu.Lock()
    if !capturing {
        mu.Unlock()
        fmt.Fprintln(w, "No capture to stop")
        return
    }

    capturing = false
    mu.Unlock()

    // シグナルを送信してキャプチャゴルーチンを停止させる
    captureStopChan <- true

    // ゴルーチンが停止するまで待機する
    captureWG.Wait()

    fmt.Fprintln(w, "Capture stopped")
}

func capturePackets() {
    defer captureWG.Done()

    handle, err := pcap.OpenLive("ens192", 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for {
        select {
        case packet := <-packetSource.Packets():
            if wsConn != nil {
                err := wsConn.WriteMessage(websocket.TextMessage, []byte(packet.String()))
                if err != nil {
                    log.Println("WebSocket write error:", err)
                    return
                }
            }
        case <-captureStopChan:
            log.Println("Capture stopped")
            return
        }
    }
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("WebSocket upgrade error:", err)
        return
    }
    defer conn.Close()

    mu.Lock()
    wsConn = conn
    mu.Unlock()

    // Wait for the WebSocket to be closed
    for {
        _, _, err := conn.NextReader()
        if err != nil {
            log.Println("WebSocket read error:", err)
            mu.Lock()
            wsConn = nil
            mu.Unlock()
            return
        }
    }
}
