package api

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// hub manages all active WebSocket connections.
var hub = &wsHub{
	clients:   make(map[*websocket.Conn]bool),
	broadcast: make(chan []byte, 256),
}

type wsHub struct {
	mu        sync.Mutex
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
}

func init() {
	go hub.run()
	go hub.generateEvents()
}

func (h *wsHub) run() {
	for msg := range h.broadcast {
		h.mu.Lock()
		for conn := range h.clients {
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				conn.Close()
				delete(h.clients, conn)
			}
		}
		h.mu.Unlock()
	}
}

func (h *wsHub) generateEvents() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	severities := []string{"low", "medium", "high", "critical"}
	categories := []string{"anomaly", "intrusion", "malware", "lateral_movement", "exfiltration", "dos"}
	sources := []string{"FIT-101", "LIT-101", "DPIT-301", "PIT-501", "Modbus", "DNP3", "S7comm", "EtherNet/IP"}
	actors := []string{"VOLTZITE", "SANDWORM", "XENOTIME", "TRITON", "RASPITE", "KAMACITE", "MAGNALLIUM"}

	for range time.Tick(30 * time.Second) {
		sev := severities[rng.Intn(len(severities))]
		cat := categories[rng.Intn(len(categories))]
		src := sources[rng.Intn(len(sources))]

		event := map[string]any{
			"id":          fmt.Sprintf("EVT-%d", time.Now().UnixMilli()),
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
			"severity":    sev,
			"category":    cat,
			"source":      src,
			"actor":       actors[rng.Intn(len(actors))],
			"description": fmt.Sprintf("Anomalous %s pattern detected on %s sensor", cat, src),
			"score":       float64(rng.Intn(100)) / 100.0,
		}

		blob, _ := json.Marshal(event)

		// Persist critical events to SQLite
		if sev == "critical" || sev == "high" {
			inc := models.Incident{
				ID:        event["id"].(string),
				Title:     event["description"].(string),
				Severity:  sev,
				Timestamp: event["timestamp"].(string),
				Source:    src,
				DataJSON:  string(blob),
			}
			db.DB.Create(&inc)
		}

		h.broadcast <- blob
	}
}

// WSHandler upgrades to WebSocket and streams threat events.
func WSHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}
	defer conn.Close()

	hub.mu.Lock()
	hub.clients[conn] = true
	hub.mu.Unlock()

	defer func() {
		hub.mu.Lock()
		delete(hub.clients, conn)
		hub.mu.Unlock()
	}()

	// Replay last 20 incidents from DB
	var recent []models.Incident
	db.DB.Order("timestamp desc").Limit(20).Find(&recent)
	for i := len(recent) - 1; i >= 0; i-- {
		var full map[string]any
		if json.Unmarshal([]byte(recent[i].DataJSON), &full) == nil {
			msg, _ := json.Marshal(gin.H{"type": "replay", "event": full})
			conn.WriteMessage(websocket.TextMessage, msg)
		}
	}

	// Keep alive until client disconnects
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
