package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

// GetThreatActors returns all threat actors with full enrichment.
func GetThreatActors(c *gin.Context) {
	var actors []models.ThreatActor
	db.DB.Find(&actors)

	results := make([]any, 0, len(actors))
	for _, a := range actors {
		enriched := enrichActor(a)
		results = append(results, enriched)
	}
	c.JSON(http.StatusOK, gin.H{"threat_actors": results})
}

// GetThreatActor returns a single actor with full enrichment.
func GetThreatActor(c *gin.Context) {
	id := c.Param("id")
	var actor models.ThreatActor
	if err := db.DB.First(&actor, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "actor not found"})
		return
	}
	c.JSON(http.StatusOK, enrichActor(actor))
}

// enrichActor merges db fields with the stored JSON blob and adds computed enrichments.
func enrichActor(a models.ThreatActor) map[string]any {
	var full map[string]any
	if err := json.Unmarshal([]byte(a.DataJSON), &full); err != nil {
		full = make(map[string]any)
	}

	// ── Normalize field names ────────────────────────────────────────────────
	// The JSON uses different field names than the frontend expects.
	// Normalize so either old or new key names work.

	// nation → nation_state
	if _, ok := full["nation_state"]; !ok {
		if n, ok := full["nation"].(string); ok {
			full["nation_state"] = n
		}
	}

	// first_seen → active_since
	if _, ok := full["active_since"]; !ok {
		if n, ok := full["first_seen"].(string); ok {
			full["active_since"] = n
		}
	}

	// targeted_sectors → target_sectors
	if _, ok := full["target_sectors"]; !ok {
		if ts, ok := full["targeted_sectors"]; ok {
			full["target_sectors"] = ts
		}
	}

	// targeted_regions → regions (expose as-is)
	if _, ok := full["regions"]; !ok {
		if tr, ok := full["targeted_regions"]; ok {
			full["regions"] = tr
		}
	}

	// mitre_techniques → techniques (for tactic breakdown lookup)
	if _, ok := full["techniques"]; !ok {
		if mt, ok := full["mitre_techniques"]; ok {
			full["techniques"] = mt
		}
	}

	// Derive category from nation if not set
	if _, ok := full["category"]; !ok {
		nation, _ := full["nation_state"].(string)
		switch nation {
		case "Russia", "China", "Iran", "North Korea", "Belarus":
			full["category"] = "nation-state"
		default:
			full["category"] = "criminal"
		}
	}

	// Derive motivation if not set
	if _, ok := full["motivation"]; !ok {
		nation, _ := full["nation_state"].(string)
		switch nation {
		case "Russia":
			full["motivation"] = "Disruption / Geopolitical"
		case "China":
			full["motivation"] = "Espionage / Pre-positioning"
		case "Iran":
			full["motivation"] = "Espionage / Sabotage"
		case "North Korea":
			full["motivation"] = "Revenue Generation / Espionage"
		default:
			full["motivation"] = "Intelligence Collection"
		}
	}

	// ── Tactic breakdown ─────────────────────────────────────────────────────
	techniqueIDs := []string{}
	if ids, ok := full["techniques"].([]any); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				techniqueIDs = append(techniqueIDs, s)
			}
		}
	}

	var techniques []models.MitreTechnique
	if len(techniqueIDs) > 0 {
		db.DB.Where("id IN ?", techniqueIDs).Find(&techniques)
	}

	var tactics []models.MitreTactic
	db.DB.Order("`order` asc").Find(&tactics)

	tacticCounts := make(map[string]int)
	for _, tech := range techniques {
		tacticCounts[tech.TacticID]++
	}

	tacticBreakdown := make([]map[string]any, 0)
	for _, t := range tactics {
		tacticBreakdown = append(tacticBreakdown, map[string]any{
			"tactic_id":   t.ID,
			"tactic_name": t.Name,
			"count":       tacticCounts[t.ID],
		})
	}

	full["tactic_breakdown"] = tacticBreakdown
	full["technique_count"] = len(techniqueIDs)

	return full
}
