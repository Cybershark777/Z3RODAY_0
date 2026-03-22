package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

// loadStaticJSON reads a JSON file and returns the value at the given top-level key.
func loadStaticJSON(path, key string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return raw[key], nil
}

// GetGeoRisk returns geo risk country data from SQLite.
func GetGeoRisk(c *gin.Context) {
	var countries []models.GeoRiskCountry
	db.DB.Find(&countries)

	results := make([]any, 0, len(countries))
	for _, co := range countries {
		var full map[string]any
		if err := json.Unmarshal([]byte(co.DataJSON), &full); err == nil {
			results = append(results, full)
		}
	}
	c.JSON(http.StatusOK, gin.H{"countries": results})
}

// GetNetworkGraph returns nodes and links from SQLite.
func GetNetworkGraph(c *gin.Context) {
	var nodes []models.NetworkNode
	db.DB.Find(&nodes)

	var links []models.NetworkLink
	db.DB.Find(&links)

	nodeResults := make([]any, 0, len(nodes))
	for _, n := range nodes {
		var full map[string]any
		if err := json.Unmarshal([]byte(n.DataJSON), &full); err == nil {
			nodeResults = append(nodeResults, full)
		}
	}

	linkResults := make([]map[string]any, 0, len(links))
	for _, l := range links {
		linkResults = append(linkResults, map[string]any{
			"source":   l.Source,
			"target":   l.Target,
			"relation": l.Relation,
		})
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodeResults, "links": linkResults})
}

// GetIncidents returns stored incidents from SQLite.
func GetIncidents(c *gin.Context) {
	var incidents []models.Incident
	db.DB.Order("timestamp desc").Limit(200).Find(&incidents)

	results := make([]any, 0, len(incidents))
	for _, inc := range incidents {
		var full map[string]any
		if err := json.Unmarshal([]byte(inc.DataJSON), &full); err == nil {
			results = append(results, full)
		} else {
			results = append(results, inc)
		}
	}
	c.JSON(http.StatusOK, gin.H{"incidents": results})
}

// CreateIncident persists a new incident (e.g., from SOAR automation).
func CreateIncident(c *gin.Context) {
	var payload map[string]any
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	blob, _ := json.Marshal(payload)
	inc := models.Incident{
		ID:       fmt.Sprintf("INC-%d", time.Now().UnixMilli()),
		Title:    fmt.Sprint(payload["title"]),
		Severity: fmt.Sprint(payload["severity"]),
		Source:   "api",
		DataJSON: string(blob),
	}
	if err := db.DB.Create(&inc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, inc)
}

// GetCorrelations computes Jaccard similarity between threats based on shared MITRE techniques.
func GetCorrelations(c *gin.Context) {
	var threats []models.Threat
	db.DB.Find(&threats)

	type threatTechs struct {
		id         string
		name       string
		techniques map[string]bool
	}

	items := make([]threatTechs, 0, len(threats))
	for _, t := range threats {
		var raw map[string]any
		json.Unmarshal([]byte(t.DataJSON), &raw)
		techSet := make(map[string]bool)
		if ids, ok := raw["mitre_ics_ids"].([]any); ok {
			for _, id := range ids {
				techSet[id.(string)] = true
			}
		}
		items = append(items, threatTechs{id: t.ID, name: t.FullName, techniques: techSet})
	}

	type cell struct {
		ThreatA string  `json:"threat_a"`
		ThreatB string  `json:"threat_b"`
		Score   float64 `json:"score"`
	}

	cells := make([]cell, 0)
	for i := 0; i < len(items); i++ {
		for j := 0; j < len(items); j++ {
			a, b := items[i].techniques, items[j].techniques
			intersection := 0
			union := len(b)
			for k := range a {
				if b[k] {
					intersection++
				} else {
					union++
				}
			}
			score := 0.0
			if union > 0 {
				score = float64(intersection) / float64(union)
			}
			cells = append(cells, cell{ThreatA: items[i].id, ThreatB: items[j].id, Score: score})
		}
	}

	labels := make([]map[string]string, 0, len(items))
	for _, it := range items {
		labels = append(labels, map[string]string{"id": it.id, "name": it.name})
	}

	c.JSON(http.StatusOK, gin.H{"labels": labels, "cells": cells})
}

// GetScenarios returns all attack scenarios from static JSON.
func GetScenarios(dataDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := loadStaticJSON(dataDir+"/scenarios.json", "scenarios")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	}
}

// GetScenario returns a single scenario by ID.
func GetScenario(dataDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		data, err := loadStaticJSON(dataDir+"/scenarios.json", "scenarios")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		scenarios, _ := data.([]any)
		for _, s := range scenarios {
			sm, _ := s.(map[string]any)
			if sm["id"] == id {
				c.JSON(http.StatusOK, sm)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "scenario not found"})
	}
}

// GetPurdue returns the Purdue Reference Model structure.
func GetPurdue(dataDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		b, err := os.ReadFile(dataDir + "/purdue.json")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var data any
		json.Unmarshal(b, &data)
		c.JSON(http.StatusOK, data)
	}
}

// GetReferences returns references from static JSON.
func GetReferences(dataDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		b, err := os.ReadFile(dataDir + "/references.json")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var data any
		json.Unmarshal(b, &data)
		c.JSON(http.StatusOK, data)
	}
}
