package api

import (
	"encoding/json"
	"log"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// WSSensorStream streams live SWaT sensor readings with real-time anomaly detection.
// Accepts {"action":"inject_attack"} messages to trigger synthetic attack windows.
func WSSensorStream(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("sensor stream upgrade error: %v", err)
		return
	}
	defer conn.Close()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	const shortW = 30
	const longW = 150
	const zWin = 60

	// Rolling history per sensor
	history := make(map[string][]float64)
	for _, s := range swatSensors {
		history[s.name] = make([]float64, 0, longW+1)
	}

	var mu sync.Mutex
	step := 0
	attackUntil := -1

	// Listen for commands from client
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var cmd map[string]any
			if json.Unmarshal(msg, &cmd) == nil {
				if cmd["action"] == "inject_attack" {
					mu.Lock()
					attackUntil = step + 40
					mu.Unlock()
				}
			}
		}
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		mu.Lock()
		curStep := step
		isAtk := curStep < attackUntil
		atkRemaining := 0
		if isAtk {
			atkRemaining = attackUntil - curStep
		}
		step++
		mu.Unlock()

		readings := make(map[string]float64)
		zScoresLive := make(map[string]float64)
		driftScoresLive := make(map[string]float64)
		ifScoresLive := make(map[string]float64)

		maxZ, maxDrift, maxIF := 0.0, 0.0, 0.0

		// Precompute IF c(n) for window size
		harmonic := 0.0
		for k := 1; k < zWin; k++ {
			harmonic += 1.0 / float64(k)
		}
		cN := 2.0*harmonic - 2.0*float64(zWin-1)/float64(zWin)

		for _, s := range swatSensors {
			v := s.base + rng.NormFloat64()*s.noise
			if isAtk {
				progress := 1.0 - float64(atkRemaining)/40.0
				v += s.base * 0.5 * progress * (0.5 + rng.Float64())
			}
			v = r3(v)
			readings[s.name] = v

			hist := history[s.name]
			hist = append(hist, v)
			if len(hist) > longW {
				hist = hist[1:]
			}
			history[s.name] = hist

			// Rolling Z-score
			if len(hist) >= 2 {
				winStart := len(hist) - zWin
				if winStart < 0 {
					winStart = 0
				}
				m, sd := meanStd(hist[winStart:])
				z := math.Abs(v-m) / sd
				zScoresLive[s.name] = r3(z)
				if z > maxZ {
					maxZ = z
				}
			}

			// Dual-window drift
			if len(hist) >= longW {
				shortVals := hist[len(hist)-shortW:]
				longVals := hist[len(hist)-longW:]
				shortM, _ := meanStd(shortVals)
				longM, longSD := meanStd(longVals)
				drift := math.Abs(shortM-longM) / longSD
				driftScoresLive[s.name] = r3(drift)
				if drift > maxDrift {
					maxDrift = drift
				}
			}

			// Isolation Forest
			if len(hist) >= zWin {
				winVals := hist[len(hist)-zWin:]
				m, sd := meanStd(winVals)
				dev := math.Abs(v-m) / sd
				pathLen := cN * math.Exp(-dev*0.35)
				ifScore := math.Pow(2.0, -pathLen/cN)
				ifScoresLive[s.name] = r3(ifScore)
				if ifScore > maxIF {
					maxIF = ifScore
				}
			}
		}

		alertLevel := "normal"
		if maxZ > 3.5 || maxIF > 0.78 || maxDrift > 2.0 {
			alertLevel = "critical"
		} else if maxZ > 2.5 || maxIF > 0.68 || maxDrift > 1.2 {
			alertLevel = "warning"
		}

		payload := map[string]any{
			"step":          curStep,
			"ts":            time.Now().UnixMilli(),
			"readings":      readings,
			"z_scores":      zScoresLive,
			"drift_scores":  driftScoresLive,
			"if_scores":     ifScoresLive,
			"max_z":         r3(maxZ),
			"max_drift":     r3(maxDrift),
			"max_if":        r3(maxIF),
			"is_attack":     isAtk,
			"atk_remaining": atkRemaining,
			"alert_level":   alertLevel,
		}

		data, _ := json.Marshal(payload)
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			return
		}
	}
}
