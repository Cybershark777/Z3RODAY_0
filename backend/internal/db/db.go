package db

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gwu/cps-threat-dashboard/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Connect opens (or creates) the SQLite database and runs migrations.
func Connect(dbPath string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	DB.Exec("PRAGMA journal_mode=WAL")
	DB.Exec("PRAGMA foreign_keys=ON")

	return DB.AutoMigrate(
		&models.Threat{},
		&models.ThreatActor{},
		&models.MitreTactic{},
		&models.MitreTechnique{},
		&models.Incident{},
		&models.APICache{},
		&models.GeoRiskCountry{},
		&models.NetworkNode{},
		&models.NetworkLink{},
		&models.SOCMetric{},
	)
}

// SeedFromJSON loads the JSON data files into SQLite if tables are empty.
func SeedFromJSON(dataDir string) error {
	seeded := 0

	// ── Threats ────────────────────────────────────────────────────────────
	var threatCount int64
	DB.Model(&models.Threat{}).Count(&threatCount)
	if threatCount == 0 {
		if err := seedThreats(filepath.Join(dataDir, "threats.json")); err != nil {
			log.Printf("warn: seed threats: %v", err)
		} else {
			seeded++
		}
	}

	// ── MITRE ──────────────────────────────────────────────────────────────
	var tacticCount int64
	DB.Model(&models.MitreTactic{}).Count(&tacticCount)
	if tacticCount == 0 {
		if err := seedMitre(filepath.Join(dataDir, "mitre_ics.json")); err != nil {
			log.Printf("warn: seed mitre: %v", err)
		} else {
			seeded++
		}
	}

	// ── Threat Actors ──────────────────────────────────────────────────────
	var actorCount int64
	DB.Model(&models.ThreatActor{}).Count(&actorCount)
	if actorCount == 0 {
		if err := seedActors(filepath.Join(dataDir, "threat_actors.json")); err != nil {
			log.Printf("warn: seed actors: %v", err)
		} else {
			seeded++
		}
	}

	// ── Geo Risk ───────────────────────────────────────────────────────────
	var geoCount int64
	DB.Model(&models.GeoRiskCountry{}).Count(&geoCount)
	if geoCount == 0 {
		if err := seedGeoRisk(filepath.Join(dataDir, "geo_risk.json")); err != nil {
			log.Printf("warn: seed geo_risk: %v", err)
		} else {
			seeded++
		}
	}

	// ── Network Graph ──────────────────────────────────────────────────────
	var nodeCount int64
	DB.Model(&models.NetworkNode{}).Count(&nodeCount)
	if nodeCount == 0 {
		if err := seedNetwork(filepath.Join(dataDir, "network_graph.json")); err != nil {
			log.Printf("warn: seed network: %v", err)
		} else {
			seeded++
		}
	}

	// ── Incidents ──────────────────────────────────────────────────────────
	var incidentCount int64
	DB.Model(&models.Incident{}).Count(&incidentCount)
	if incidentCount == 0 {
		if err := seedIncidents(filepath.Join(dataDir, "incidents.json")); err != nil {
			log.Printf("warn: seed incidents: %v", err)
		} else {
			seeded++
		}
	}

	if seeded > 0 {
		log.Printf("✔ Seeded %d collection(s) into SQLite", seeded)
	} else {
		log.Println("✔ Database already seeded — skipping")
	}
	return nil
}

// ── Seed helpers ────────────────────────────────────────────────────────────

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func seedThreats(path string) error {
	var raw struct {
		ThreatCategories []map[string]any `json:"threat_categories"`
		SocMetrics       map[string]any   `json:"soc_metrics"`
	}
	if err := readJSON(path, &raw); err != nil {
		return err
	}

	for _, t := range raw.ThreatCategories {
		blob, _ := json.Marshal(t)
		severity := ""
		severityScore := 0
		if s, ok := t["severity"].(map[string]any); ok {
			severity, _ = s["level"].(string)
			if sc, ok := s["score"].(float64); ok {
				severityScore = int(sc)
			}
		}
		layer := ""
		if l, ok := t["layer"].(string); ok {
			layer = l
		}
		eventCount := 0
		if ec, ok := t["event_count"].(float64); ok {
			eventCount = int(ec)
		}
		record := models.Threat{
			ID:            fmt.Sprint(t["id"]),
			FullName:      fmt.Sprint(t["full_name"]),
			Category:      fmt.Sprint(t["category"]),
			Layer:         layer,
			Severity:      severity,
			SeverityScore: severityScore,
			EventCount:    eventCount,
			DataJSON:      string(blob),
		}
		DB.Create(&record)
	}

	// Seed SOC metrics
	if raw.SocMetrics != nil {
		for k, v := range raw.SocMetrics {
			val := 0.0
			unit := ""
			if m, ok := v.(map[string]any); ok {
				if fv, ok := m["value"].(float64); ok {
					val = fv
				}
				unit, _ = m["unit"].(string)
			} else if fv, ok := v.(float64); ok {
				val = fv
			}
			DB.Save(&models.SOCMetric{ID: k, Label: k, Value: val, Unit: unit})
		}
	}
	return nil
}

func seedMitre(path string) error {
	var raw map[string]any
	if err := readJSON(path, &raw); err != nil {
		return err
	}

	if tactics, ok := raw["tactics"].([]any); ok {
		for i, t := range tactics {
			tm := t.(map[string]any)
			blob, _ := json.Marshal(tm)
			DB.Create(&models.MitreTactic{
				ID:       fmt.Sprint(tm["id"]),
				Name:     fmt.Sprint(tm["name"]),
				ShortID:  fmt.Sprint(tm["short_id"]),
				Order:    i,
				DataJSON: string(blob),
			})
		}
	}

	if techniques, ok := raw["techniques"].([]any); ok {
		for _, t := range techniques {
			tm := t.(map[string]any)
			blob, _ := json.Marshal(tm)
			DB.Create(&models.MitreTechnique{
				ID:          fmt.Sprint(tm["id"]),
				Name:        fmt.Sprint(tm["name"]),
				TacticID:    fmt.Sprint(tm["tactic_id"]),
				Description: fmt.Sprint(tm["description"]),
				DataJSON:    string(blob),
			})
		}
	}
	return nil
}

func seedActors(path string) error {
	var raw struct {
		ThreatActors []map[string]any `json:"threat_actors"`
	}
	if err := readJSON(path, &raw); err != nil {
		return err
	}

	for _, a := range raw.ThreatActors {
		blob, _ := json.Marshal(a)
		ns := ""
		if n, ok := a["nation_state"].(string); ok {
			ns = n
		}
		motivation := ""
		if m, ok := a["motivation"].(string); ok {
			motivation = m
		}
		category := ""
		if c, ok := a["category"].(string); ok {
			category = c
		}
		activeSince := ""
		if as, ok := a["active_since"].(string); ok {
			activeSince = as
		}
		DB.Create(&models.ThreatActor{
			ID:          fmt.Sprint(a["id"]),
			Name:        fmt.Sprint(a["name"]),
			NationState: ns,
			Category:    category,
			ActiveSince: activeSince,
			Motivation:  motivation,
			DataJSON:    string(blob),
		})
	}
	return nil
}

func seedGeoRisk(path string) error {
	var raw struct {
		Countries []map[string]any `json:"countries"`
	}
	if err := readJSON(path, &raw); err != nil {
		return err
	}

	for _, c := range raw.Countries {
		blob, _ := json.Marshal(c)
		role := ""
		if r, ok := c["role"].(string); ok {
			role = r
		}
		code := ""
		if co, ok := c["code"].(string); ok {
			code = co
		}
		name := ""
		if n, ok := c["name"].(string); ok {
			name = n
		}
		DB.Create(&models.GeoRiskCountry{
			Code:     code,
			Name:     name,
			Role:     role,
			DataJSON: string(blob),
		})
	}
	return nil
}

func seedNetwork(path string) error {
	var raw struct {
		Nodes []map[string]any `json:"nodes"`
		Links []map[string]any `json:"links"`
	}
	if err := readJSON(path, &raw); err != nil {
		return err
	}

	for _, n := range raw.Nodes {
		blob, _ := json.Marshal(n)
		DB.Create(&models.NetworkNode{
			ID:       fmt.Sprint(n["id"]),
			Label:    fmt.Sprint(n["label"]),
			Type:     fmt.Sprint(n["type"]),
			DataJSON: string(blob),
		})
	}

	for _, l := range raw.Links {
		source := fmt.Sprint(l["source"])
		target := fmt.Sprint(l["target"])
		relation := ""
		if r, ok := l["relation"].(string); ok {
			relation = r
		}
		DB.Create(&models.NetworkLink{
			Source:   source,
			Target:   target,
			Relation: relation,
		})
	}
	return nil
}

func seedIncidents(path string) error {
	var raw struct {
		Incidents []map[string]any `json:"incidents"`
	}
	if err := readJSON(path, &raw); err != nil {
		return err
	}

	for _, inc := range raw.Incidents {
		blob, _ := json.Marshal(inc)
		DB.Create(&models.Incident{
			ID:        fmt.Sprint(inc["id"]),
			Title:     fmt.Sprint(inc["title"]),
			Severity:  fmt.Sprint(inc["severity"]),
			Timestamp: fmt.Sprint(inc["timestamp"]),
			Source:    fmt.Sprint(inc["source"]),
			DataJSON:  string(blob),
		})
	}
	return nil
}
