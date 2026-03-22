package api

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/cache"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	nvdBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

var icsKeywords = []string{
	"ics", "scada", "modbus", "dnp3", "ot", "industrial", "plc", "controller",
	"historian", "hmi", "siemens", "rockwell", "schneider", "abb", "honeywell",
}

// GetKEV fetches CISA KEV data filtered for ICS/OT relevance.
func GetKEV(c *gin.Context) {
	const cacheKey = "kev"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	resp, err := httpGet(kevURL)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var raw struct {
		Vulnerabilities []map[string]any `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	filtered := make([]map[string]any, 0)
	for _, v := range raw.Vulnerabilities {
		text := strings.ToLower(fmt.Sprint(v["shortDescription"]) + fmt.Sprint(v["product"]) + fmt.Sprint(v["vendorProject"]))
		for _, kw := range icsKeywords {
			if strings.Contains(text, kw) {
				filtered = append(filtered, v)
				break
			}
		}
	}

	result := gin.H{"vulnerabilities": filtered, "total": len(filtered), "source": "CISA KEV"}
	cache.Default.Set(cacheKey, result, time.Hour)
	c.JSON(http.StatusOK, result)
}

// GetCVE fetches CVEs from NVD for a given keyword.
func GetCVE(c *gin.Context) {
	keyword := c.Query("keyword")
	if keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "keyword query param required"})
		return
	}

	cacheKey := "nvd-" + keyword
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	url := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=20", nvdBase, keyword)
	resp, err := httpGet(url)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var raw map[string]any
	json.NewDecoder(resp.Body).Decode(&raw)

	cache.Default.Set(cacheKey, raw, 2*time.Hour)
	c.JSON(http.StatusOK, raw)
}

// GetOTX returns AlienVault OTX pulses for ICS/OT.
func GetOTX(c *gin.Context) {
	const cacheKey = "otx"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	apiKey := os.Getenv("OTX_API_KEY")
	if apiKey == "" {
		c.JSON(http.StatusOK, gin.H{"pulses": []any{}, "notice": "OTX_API_KEY not set", "active": false})
		return
	}

	url := "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&page=1"
	req, _ := newRequest("GET", url, nil)
	req.Header.Set("X-OTX-API-KEY", apiKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error(), "active": false})
		return
	}
	defer resp.Body.Close()

	var raw map[string]any
	json.NewDecoder(resp.Body).Decode(&raw)

	result := gin.H{"pulses": raw["results"], "active": true, "count": raw["count"]}
	cache.Default.Set(cacheKey, result, 15*time.Minute)
	c.JSON(http.StatusOK, result)
}

// GetNews returns aggregated ICS/OT security news via RSS feeds.
func GetNews(c *gin.Context) {
	const cacheKey = "news"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	feeds := []string{
		"https://www.cisa.gov/uscert/ncas/current-activity.xml",
		"https://feeds.feedburner.com/eset/blog",
	}

	articles := make([]map[string]any, 0)
	for _, feedURL := range feeds {
		resp, err := httpGet(feedURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		parsed := parseRSS(resp)
		articles = append(articles, parsed...)
	}

	result := gin.H{"articles": articles, "count": len(articles)}
	cache.Default.Set(cacheKey, result, 20*time.Minute)
	c.JSON(http.StatusOK, result)
}

// GetBriefing returns an AI-generated threat briefing via the Anthropic API.
func GetBriefing(c *gin.Context) {
	const cacheKey = "briefing"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		c.JSON(http.StatusOK, gin.H{"briefing": "ANTHROPIC_API_KEY not configured.", "cached": false})
		return
	}

	// Build context from DB
	var actors []models.ThreatActor
	db.DB.Limit(5).Find(&actors)
	actorNames := make([]string, 0)
	for _, a := range actors {
		actorNames = append(actorNames, a.Name)
	}

	prompt := fmt.Sprintf(`You are a senior ICS/OT security analyst. Write a concise tactical threat briefing (400–500 words) for a CPS data center security operations team. Include:
1. Current threat landscape for ICS/OT environments
2. Key threat actors active against critical infrastructure: %s
3. Top 3 attack vectors targeting Purdue Model Levels 0-2
4. Recommended defensive actions for SOC teams
5. Relevant MITRE ATT&CK for ICS techniques to monitor

Format with ## headings, bullet points, and a --- separator before recommendations.`,
		strings.Join(actorNames, ", "))

	body := map[string]any{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 1024,
		"messages":   []map[string]any{{"role": "user", "content": prompt}},
	}
	bodyBytes, _ := json.Marshal(body)

	req, _ := newRequest("POST", "https://api.anthropic.com/v1/messages", bodyBytes)
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var raw map[string]any
	json.NewDecoder(resp.Body).Decode(&raw)

	briefing := ""
	if content, ok := raw["content"].([]any); ok && len(content) > 0 {
		if block, ok := content[0].(map[string]any); ok {
			briefing, _ = block["text"].(string)
		}
	}

	result := gin.H{"briefing": briefing, "cached": false, "generated_at": time.Now().UTC().Format(time.RFC3339)}
	cache.Default.Set(cacheKey, result, 30*time.Minute)
	c.JSON(http.StatusOK, result)
}

// GetThreatFeed returns recent threat events from SQLite incidents.
func GetThreatFeed(c *gin.Context) {
	var incidents []models.Incident
	db.DB.Order("timestamp desc").Limit(50).Find(&incidents)

	events := make([]any, 0, len(incidents))
	for _, inc := range incidents {
		var full map[string]any
		if json.Unmarshal([]byte(inc.DataJSON), &full) == nil {
			events = append(events, full)
		}
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "count": len(events)})
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

func httpGet(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CPS-Threat-Dashboard/2.0")
	return client.Do(req)
}

func newRequest(method, url string, body []byte) (*http.Request, error) {
	if body != nil {
		return http.NewRequest(method, url, strings.NewReader(string(body)))
	}
	return http.NewRequest(method, url, nil)
}

func parseRSS(resp *http.Response) []map[string]any {
	// Minimal RSS parsing — extract title + link + pubDate
	var raw struct {
		Channel struct {
			Items []struct {
				Title   string `xml:"title"`
				Link    string `xml:"link"`
				PubDate string `xml:"pubDate"`
				Desc    string `xml:"description"`
			} `xml:"item"`
		} `xml:"channel"`
	}

	decoder := xml.NewDecoder(resp.Body)
	decoder.Strict = false
	xml.NewDecoder(resp.Body).Decode(&raw)

	results := make([]map[string]any, 0, len(raw.Channel.Items))
	for _, item := range raw.Channel.Items {
		results = append(results, map[string]any{
			"title":    item.Title,
			"link":     item.Link,
			"pub_date": item.PubDate,
			"summary":  item.Desc,
		})
	}
	return results
}
