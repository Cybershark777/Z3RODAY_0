package models

import "time"

// ── Threat ─────────────────────────────────────────────────────────────────

type Threat struct {
	ID            string    `gorm:"primaryKey" json:"id"`
	FullName      string    `json:"full_name"`
	Category      string    `json:"category"`
	Layer         string    `json:"layer"`
	Severity      string    `json:"severity"`
	SeverityScore int       `json:"severity_score"`
	EventCount    int       `json:"event_count"`
	DataJSON      string    `gorm:"column:data_json" json:"-"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ── ThreatActor ────────────────────────────────────────────────────────────

type ThreatActor struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	NationState string    `json:"nation_state"`
	Category    string    `json:"category"`
	ActiveSince string    `json:"active_since"`
	Motivation  string    `json:"motivation"`
	DataJSON    string    `gorm:"column:data_json" json:"-"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ── MitreTactic ───────────────────────────────────────────────────────────

type MitreTactic struct {
	ID       string `gorm:"primaryKey" json:"id"`
	Name     string `json:"name"`
	ShortID  string `json:"short_id"`
	Order    int    `json:"order"`
	DataJSON string `gorm:"column:data_json" json:"-"`
}

// ── MitreTechnique ────────────────────────────────────────────────────────

type MitreTechnique struct {
	ID          string `gorm:"primaryKey" json:"id"`
	Name        string `json:"name"`
	TacticID    string `json:"tactic_id"`
	Description string `json:"description"`
	DataJSON    string `gorm:"column:data_json" json:"-"`
}

// ── Incident ──────────────────────────────────────────────────────────────

type Incident struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Timestamp string    `json:"timestamp"`
	Source    string    `json:"source"`
	DataJSON  string    `gorm:"column:data_json" json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// ── APICache ──────────────────────────────────────────────────────────────

type APICache struct {
	Key       string `gorm:"primaryKey" json:"key"`
	Data      string `json:"data"`
	ExpiresAt int64  `json:"expires_at"`
}

// ── GeoRiskCountry ────────────────────────────────────────────────────────

type GeoRiskCountry struct {
	Code     string `gorm:"primaryKey" json:"code"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	DataJSON string `gorm:"column:data_json" json:"-"`
}

// ── NetworkNode ───────────────────────────────────────────────────────────

type NetworkNode struct {
	ID       string `gorm:"primaryKey" json:"id"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	DataJSON string `gorm:"column:data_json" json:"-"`
}

// ── NetworkLink ───────────────────────────────────────────────────────────

type NetworkLink struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

// ── SOCMetric ────────────────────────────────────────────────────────────

type SOCMetric struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Label     string    `json:"label"`
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	UpdatedAt time.Time `json:"updated_at"`
}
