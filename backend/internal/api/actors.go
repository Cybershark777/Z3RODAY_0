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

	// Inject technique tactic mapping for per-actor ATT&CK heatmap
	techniqueIDs := []string{}
	if ids, ok := full["techniques"].([]any); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				techniqueIDs = append(techniqueIDs, s)
			}
		}
	}

	// Build tactic → technique count for this actor
	var techniques []models.MitreTechnique
	if len(techniqueIDs) > 0 {
		db.DB.Where("id IN ?", techniqueIDs).Find(&techniques)
	}

	var tactics []models.MitreTactic
	db.DB.Order("`order` asc").Find(&tactics)

	tacticNames := make(map[string]string)
	for _, t := range tactics {
		tacticNames[t.ID] = t.Name
	}

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
