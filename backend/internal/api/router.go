package api

import (
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// NewRouter wires all routes and returns a configured gin.Engine.
func NewRouter(dataDir string) *gin.Engine {
	r := gin.Default()

	// CORS — allow all origins for the dev React frontend
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
	}))

	// Health
	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "cps-threat-dashboard"})
	})

	// ── Core data endpoints ─────────────────────────────────────────────────
	r.GET("/api/threats", GetThreats)
	r.GET("/api/threats/:id", GetThreat)
	r.GET("/api/metrics", GetMetrics)
	r.GET("/api/datasets", GetDatasets(dataDir))

	// ── MITRE ATT&CK ICS ───────────────────────────────────────────────────
	r.GET("/api/mitre/tactics", GetMitreTactics)
	r.GET("/api/mitre/techniques", GetMitreTechniques)
	r.GET("/api/mitre/heatmap", GetMitreHeatmap)
	r.GET("/api/mitre/threat/:threatId", GetMitreForThreat)

	// ── Attack Scenarios ────────────────────────────────────────────────────
	r.GET("/api/scenarios", GetScenarios(dataDir))
	r.GET("/api/scenarios/:id", GetScenario(dataDir))
	r.GET("/api/purdue", GetPurdue(dataDir))

	// ── Threat Correlation ──────────────────────────────────────────────────
	r.GET("/api/correlations", GetCorrelations)

	// ── Threat Actors ───────────────────────────────────────────────────────
	r.GET("/api/threat-actors", GetThreatActors)
	r.GET("/api/threat-actors/:id", GetThreatActor)

	// ── Geo Risk ────────────────────────────────────────────────────────────
	r.GET("/api/geo-risk", GetGeoRisk)

	// ── Network Graph ───────────────────────────────────────────────────────
	r.GET("/api/network-graph", GetNetworkGraph)

	// ── Incidents ───────────────────────────────────────────────────────────
	r.GET("/api/incidents", GetIncidents)
	r.POST("/api/incidents", CreateIncident)

	// ── ML Detection ────────────────────────────────────────────────────────
	r.GET("/api/ml-detection", GetMLDetection)

	// ── CVE Asset Map ───────────────────────────────────────────────────────
	r.GET("/api/cve-asset-map", GetCVEAssetMap)

	// ── Kill Chain ──────────────────────────────────────────────────────────
	r.GET("/api/kill-chain-techniques", GetKillChainTechniques)

	// ── Live Intel (external) ───────────────────────────────────────────────
	r.GET("/api/live/kev", GetKEV)
	r.GET("/api/live/cve", GetCVE)
	r.GET("/api/live/otx", GetOTX)
	r.GET("/api/live/news", GetNews)
	r.GET("/api/live/briefing", GetBriefing)
	r.GET("/api/live/briefing/stream", GetBriefingStream)
	r.GET("/api/threat-feed", GetThreatFeed)

	// ── References ──────────────────────────────────────────────────────────
	r.GET("/api/references", GetReferences(dataDir))

	// ── Threat Intelligence Platforms ───────────────────────────────────────
	r.GET("/api/intel/summary", GetThreatIntelSummary)
	r.GET("/api/intel/threatfox", GetThreatFoxIOCs)
	r.GET("/api/intel/threatfox/search", GetThreatFoxSearch)
	r.GET("/api/intel/feodo", GetFeodoBlocklist)
	r.GET("/api/intel/urlhaus", GetURLhausRecent)
	r.GET("/api/intel/malwarebazaar", GetMalwareBazaarRecent)
	r.GET("/api/intel/cisa-advisories", GetCISAAdvisories)
	r.GET("/api/intel/greynoise", GetGreyNoiseICS)
	r.GET("/api/intel/greynoise/:ip", GetGreyNoiseIP)
	r.GET("/api/intel/shodan", GetShodanICS)
	r.GET("/api/intel/ioc-search", GetIOCSearch)

	// ── WebSocket ───────────────────────────────────────────────────────────
	r.GET("/ws/threatfeed", WSHandler)

	return r
}
