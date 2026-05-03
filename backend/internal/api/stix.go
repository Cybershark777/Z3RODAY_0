package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

// GetSTIXActor returns a STIX 2.1 bundle for a threat actor.
func GetSTIXActor(c *gin.Context) {
	id := c.Param("id")
	var actor models.ThreatActor
	if err := db.DB.First(&actor, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "actor not found"})
		return
	}

	var full map[string]any
	if err := json.Unmarshal([]byte(actor.DataJSON), &full); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "parse error"})
		return
	}

	enrichActor(actor) // normalise field names

	now := time.Now().UTC().Format(time.RFC3339)

	// Deterministic UUID from actor ID
	bundleID := stixUUID("bundle", id)
	intrusionID := stixUUID("intrusion-set", id)

	// Extract fields with fallbacks
	name := actor.Name
	aliases, _ := full["aliases"].([]any)
	description, _ := full["description"].(string)
	nation, _ := full["nation_state"].(string)
	if nation == "" {
		nation, _ = full["nation"].(string)
	}
	motivation := nationMotivation(nation)

	aliasStrings := make([]string, 0)
	for _, a := range aliases {
		if s, ok := a.(string); ok {
			aliasStrings = append(aliasStrings, s)
		}
	}

	// Techniques as attack-pattern references
	var techniques []any
	if t, ok := full["techniques"].([]any); ok {
		techniques = t
	} else if t, ok := full["mitre_techniques"].([]any); ok {
		techniques = t
	}

	attackPatterns := make([]map[string]any, 0)
	relationships := make([]map[string]any, 0)
	for _, t := range techniques {
		tid := fmt.Sprint(t)
		apID := stixUUID("attack-pattern", tid)
		attackPatterns = append(attackPatterns, map[string]any{
			"type":         "attack-pattern",
			"spec_version": "2.1",
			"id":           "attack-pattern--" + apID,
			"name":         tid,
			"external_references": []map[string]any{{
				"source_name": "mitre-ics-attack",
				"external_id": tid,
				"url":         fmt.Sprintf("https://attack.mitre.org/techniques/%s/", tid),
			}},
			"created":  now,
			"modified": now,
		})
		relID := stixUUID("relationship", intrusionID+"-"+apID)
		relationships = append(relationships, map[string]any{
			"type":                "relationship",
			"spec_version":        "2.1",
			"id":                  "relationship--" + relID,
			"relationship_type":   "uses",
			"source_ref":          "intrusion-set--" + intrusionID,
			"target_ref":          "attack-pattern--" + apID,
			"created":             now,
			"modified":            now,
		})
	}

	intrusionSet := map[string]any{
		"type":               "intrusion-set",
		"spec_version":       "2.1",
		"id":                 "intrusion-set--" + intrusionID,
		"name":               name,
		"description":        description,
		"aliases":            aliasStrings,
		"primary_motivation": motivation,
		"created":            now,
		"modified":           now,
	}

	objects := []any{intrusionSet}
	for _, ap := range attackPatterns {
		objects = append(objects, ap)
	}
	for _, rel := range relationships {
		objects = append(objects, rel)
	}

	bundle := map[string]any{
		"type":         "bundle",
		"id":           "bundle--" + bundleID,
		"spec_version": "2.1",
		"objects":      objects,
	}

	c.JSON(http.StatusOK, bundle)
}

func stixUUID(objType, seed string) string {
	h := sha256.Sum256([]byte(objType + ":" + seed))
	b := h[:]
	// Format as UUID v4-like: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func nationMotivation(nation string) string {
	switch strings.ToLower(nation) {
	case "russia":
		return "ideology"
	case "china":
		return "organizational-gain"
	case "iran":
		return "ideology"
	case "north korea":
		return "personal-gain"
	default:
		return "unknown"
	}
}
