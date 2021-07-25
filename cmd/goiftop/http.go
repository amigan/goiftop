package main

import (
	"encoding/json"
	"net/http"

	"github.com/amigan/goiftop/internal/log"
	"github.com/gorilla/websocket"
)

func L3FlowHandler(w http.ResponseWriter, r *http.Request) {
	resJson, err := json.Marshal(L3FlowSnapshots)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resJson)
}

func L4FlowHandler(w http.ResponseWriter, r *http.Request) {
	resJson, err := json.Marshal(L4FlowSnapshots)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resJson)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize: 1024,
	WriteBufferSize: 1024,
}

func WsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	for {
		msgType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}

	}
}
