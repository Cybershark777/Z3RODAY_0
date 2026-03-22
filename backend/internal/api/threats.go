package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

// GetThreats returns all threats with their full data blobs.
func GetThreats(c *gin.Context) {
	var threats []models.Threat
	if err := db.DB.Find(&threats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	results := make([]any, 0, len(threats))
	for _, t := range threats {
		var full map[string]any
		if err := json.Unmarshal([]byte(t.DataJSON), &full); err == nil {
			results = append(results, full)
		} else {
			results = append(results, t)
		}
	}
	c.JSON(http.StatusOK, results)
}

// GetThreat returns a single threat by ID.
func GetThreat(c *gin.Context) {
	id := c.Param("id")
	var t models.Threat
	if err := db.DB.First(&t, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "threat not found"})
		return
	}
	var full map[string]any
	if err := json.Unmarshal([]byte(t.DataJSON), &full); err == nil {
		c.JSON(http.StatusOK, full)
	} else {
		c.JSON(http.StatusOK, t)
	}
}

// GetMetrics returns SOC metrics.
func GetMetrics(c *gin.Context) {
	var metrics []models.SOCMetric
	db.DB.Find(&metrics)

	result := make(map[string]any)
	for _, m := range metrics {
		result[m.ID] = gin.H{"value": m.Value, "unit": m.Unit, "label": m.Label}
	}
	c.JSON(http.StatusOK, result)
}

// GetDatasets returns dataset summary from static JSON.
func GetDatasets(dataDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := loadStaticJSON(dataDir+"/threats.json", "dataset_summary")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	}
}
