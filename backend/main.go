package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gwu/cps-threat-dashboard/internal/api"
	"github.com/gwu/cps-threat-dashboard/internal/cache"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env from project root or backend-go dir
	_ = godotenv.Load(".env")
	_ = godotenv.Load("../.env")
	_ = godotenv.Load(filepath.Join(filepath.Dir(os.Args[0]), ".env"))

	// ── Database ────────────────────────────────────────────────────────────
	dbPath := envOrDefault("DB_PATH", "cps_dashboard.db")
	if err := db.Connect(dbPath); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	log.Printf("✔ SQLite database connected: %s", dbPath)

	// ── Seed from JSON data files ───────────────────────────────────────────
	dataDir := envOrDefault("DATA_DIR", "./data")
	if err := db.SeedFromJSON(dataDir); err != nil {
		log.Printf("warn: seed error: %v", err)
	}

	// ── Cache janitor ───────────────────────────────────────────────────────
	cache.Default.StartJanitor(5 * time.Minute)

	// ── HTTP server ─────────────────────────────────────────────────────────
	port := envOrDefault("PORT", "8001")
	router := api.NewRouter(dataDir)

	log.Printf("✔ CPS Threat Dashboard API starting on :%s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
