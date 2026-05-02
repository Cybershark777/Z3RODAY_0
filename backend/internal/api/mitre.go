package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

func GetMitreTactics(c *gin.Context) {
	var tactics []models.MitreTactic
	db.DB.Order("`order` asc").Find(&tactics)

	results := make([]any, 0, len(tactics))
	for _, t := range tactics {
		var full map[string]any
		if err := json.Unmarshal([]byte(t.DataJSON), &full); err == nil {
			results = append(results, full)
		}
	}
	c.JSON(http.StatusOK, results)
}

func GetMitreTechniques(c *gin.Context) {
	var techniques []models.MitreTechnique
	db.DB.Find(&techniques)

	// Build tactic name map
	var tactics []models.MitreTactic
	db.DB.Find(&tactics)
	tacticNames := make(map[string]string)
	for _, t := range tactics {
		tacticNames[t.ID] = t.Name
	}

	// Count actor attributions per technique
	var actors []models.ThreatActor
	db.DB.Find(&actors)
	actorCount := make(map[string]int)   // technique_id → count
	actorNames := make(map[string][]string) // technique_id → actor names
	for _, actor := range actors {
		var raw map[string]any
		if json.Unmarshal([]byte(actor.DataJSON), &raw) != nil {
			continue
		}
		ids, _ := raw["mitre_techniques"].([]any)
		if len(ids) == 0 {
			ids, _ = raw["techniques"].([]any)
		}
		for _, id := range ids {
			tid := fmt.Sprint(id)
			actorCount[tid]++
			actorNames[tid] = append(actorNames[tid], actor.Name)
		}
	}

	results := make([]any, 0, len(techniques))
	for _, tech := range techniques {
		var full map[string]any
		if err := json.Unmarshal([]byte(tech.DataJSON), &full); err == nil {
			full["tactic_name"] = tacticNames[tech.TacticID]
			full["actor_count"] = actorCount[tech.ID]
			full["actor_names"] = actorNames[tech.ID]
			results = append(results, full)
		}
	}
	c.JSON(http.StatusOK, results)
}

// GetMitreHeatmap returns tactics + technique counts per threat actor for the heatmap.
func GetMitreHeatmap(c *gin.Context) {
	var tactics []models.MitreTactic
	db.DB.Order("`order` asc").Find(&tactics)

	var techniques []models.MitreTechnique
	db.DB.Find(&techniques)

	techMap := make(map[string]string) // technique_id → tactic_id
	for _, t := range techniques {
		techMap[t.ID] = t.TacticID
	}

	var actors []models.ThreatActor
	db.DB.Find(&actors)

	// Count technique hits per (actor, tactic)
	type cell struct {
		Actor      string `json:"actor"`
		TacticID   string `json:"tactic_id"`
		TacticName string `json:"tactic_name"`
		Count      int    `json:"count"`
	}

	tacticOrder := make(map[string]int)
	for _, t := range tactics {
		tacticOrder[t.ID] = t.Order
	}
	tacticNames := make(map[string]string)
	for _, t := range tactics {
		tacticNames[t.ID] = t.Name
	}

	var cells []cell
	for _, actor := range actors {
		var raw map[string]any
		if err := json.Unmarshal([]byte(actor.DataJSON), &raw); err != nil {
			continue
		}
		actorTechniques, _ := raw["techniques"].([]any)
		if len(actorTechniques) == 0 {
			actorTechniques, _ = raw["mitre_techniques"].([]any)
		}
		counts := make(map[string]int)
		for _, tid := range actorTechniques {
			tidStr, _ := tid.(string)
			if tacticID, ok := techMap[tidStr]; ok {
				counts[tacticID]++
			}
		}
		for tacticID, count := range counts {
			cells = append(cells, cell{
				Actor:      actor.Name,
				TacticID:   tacticID,
				TacticName: tacticNames[tacticID],
				Count:      count,
			})
		}
	}

	// Sort tactics by order
	tacticList := make([]map[string]any, 0, len(tactics))
	for _, t := range tactics {
		var full map[string]any
		json.Unmarshal([]byte(t.DataJSON), &full)
		tacticList = append(tacticList, full)
	}
	sort.Slice(tacticList, func(i, j int) bool {
		return tacticOrder[tacticList[i]["id"].(string)] < tacticOrder[tacticList[j]["id"].(string)]
	})

	c.JSON(http.StatusOK, gin.H{
		"tactics": tacticList,
		"cells":   cells,
	})
}

func GetMitreForThreat(c *gin.Context) {
	threatID := c.Param("threatId")

	var threat models.Threat
	if err := db.DB.First(&threat, "id = ?", threatID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "threat not found"})
		return
	}

	var raw map[string]any
	json.Unmarshal([]byte(threat.DataJSON), &raw)
	techniqueIDs := []string{}
	if ids, ok := raw["mitre_ics_ids"].([]any); ok {
		for _, id := range ids {
			techniqueIDs = append(techniqueIDs, id.(string))
		}
	}

	var tactics []models.MitreTactic
	db.DB.Find(&tactics)
	tacticNames := make(map[string]string)
	for _, t := range tactics {
		tacticNames[t.ID] = t.Name
	}

	chain := make([]map[string]any, 0)
	for _, tid := range techniqueIDs {
		var tech models.MitreTechnique
		if err := db.DB.First(&tech, "id = ?", tid).Error; err != nil {
			continue
		}
		var full map[string]any
		json.Unmarshal([]byte(tech.DataJSON), &full)
		full["tactic_name"] = tacticNames[tech.TacticID]
		chain = append(chain, full)
	}

	c.JSON(http.StatusOK, gin.H{
		"threat_id":   threatID,
		"threat_name": threat.FullName,
		"chain":       chain,
	})
}
