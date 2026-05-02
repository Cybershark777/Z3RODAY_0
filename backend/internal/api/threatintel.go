package api

// Threat Intelligence integrations:
//   - ThreatFox     (Abuse.ch) — active C2/malware IOCs
//   - Feodo Tracker (Abuse.ch) — botnet C2 IP blocklist
//   - URLhaus       (Abuse.ch) — malicious URL feed
//   - MalwareBazaar (Abuse.ch) — recent ICS-relevant malware samples
//   - CISA ICS Advisories     — official ICS-CERT advisory RSS
//   - GreyNoise               — ICS scanner noise vs targeted attacks
//   - Shodan                  — internet-exposed ICS devices (Modbus, S7, DNP3)

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/cache"
)

// ── ThreatFox (Abuse.ch) ───────────────────────────────────────────────────

// GetThreatFoxIOCs returns recent malware IOCs from ThreatFox filtered for ICS relevance.
func GetThreatFoxIOCs(c *gin.Context) {
	const cacheKey = "threatfox-iocs"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	// ThreatFox free API — no key required for recent IOCs
	payload := map[string]any{"query": "get_iocs", "days": 7}
	data, err := abusePost("https://threatfox-api.abuse.ch/api/v1/", payload)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	raw := data["data"]
	iocs := []any{}
	if list, ok := raw.([]any); ok {
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			// Filter for ICS/OT-relevant tags and malware families
			tags := strings.ToLower(fmt.Sprint(m["tags"]))
			malware := strings.ToLower(fmt.Sprint(m["malware_printable"]))
			combined := tags + malware
			if isICSRelevant(combined) || len(iocs) < 50 {
				iocs = append(iocs, m)
			}
		}
	}

	result := gin.H{
		"iocs":       iocs,
		"total":      len(iocs),
		"source":     "ThreatFox (Abuse.ch)",
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, 15*time.Minute)
	c.JSON(http.StatusOK, result)
}

// GetThreatFoxSearch searches ThreatFox for a specific IOC value.
func GetThreatFoxSearch(c *gin.Context) {
	ioc := c.Query("ioc")
	if ioc == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ioc query param required"})
		return
	}

	cacheKey := "threatfox-search-" + ioc
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	payload := map[string]any{"query": "search_ioc", "search_term": ioc}
	data, err := abusePost("https://threatfox-api.abuse.ch/api/v1/", payload)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	result := gin.H{"result": data, "ioc": ioc, "source": "ThreatFox"}
	cache.Default.Set(cacheKey, result, 30*time.Minute)
	c.JSON(http.StatusOK, result)
}

// ── Feodo Tracker (Abuse.ch) ──────────────────────────────────────────────

// GetFeodoBlocklist returns the current Feodo botnet C2 IP blocklist.
func GetFeodoBlocklist(c *gin.Context) {
	const cacheKey = "feodo-blocklist"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	resp, err := httpGet("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var raw []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Classify entries — flag ones associated with ICS malware families
	icsEntries := []map[string]any{}
	for _, entry := range raw {
		malware := strings.ToLower(fmt.Sprint(entry["malware"]))
		if isICSMalware(malware) {
			entry["ics_relevant"] = true
			icsEntries = append(icsEntries, entry)
		} else {
			entry["ics_relevant"] = false
		}
	}

	result := gin.H{
		"blocklist":    raw,
		"ics_relevant": icsEntries,
		"total":        len(raw),
		"ics_total":    len(icsEntries),
		"source":       "Feodo Tracker (Abuse.ch)",
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, 30*time.Minute)
	c.JSON(http.StatusOK, result)
}

// ── URLhaus (Abuse.ch) ────────────────────────────────────────────────────

// GetURLhausRecent returns recent malicious URLs, filtered for ICS/OT relevance.
func GetURLhausRecent(c *gin.Context) {
	const cacheKey = "urlhaus-recent"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	data, err := abusePost("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/", nil)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	allURLs := []any{}
	icsURLs := []any{}
	if urls, ok := data["urls"].([]any); ok {
		for _, u := range urls {
			m, ok := u.(map[string]any)
			if !ok {
				continue
			}
			allURLs = append(allURLs, m)
			tags := strings.ToLower(fmt.Sprint(m["tags"]))
			urlstr := strings.ToLower(fmt.Sprint(m["url"]))
			if isICSRelevant(tags + urlstr) {
				icsURLs = append(icsURLs, m)
			}
		}
	}

	result := gin.H{
		"urls":       allURLs,
		"ics_urls":   icsURLs,
		"total":      len(allURLs),
		"ics_total":  len(icsURLs),
		"source":     "URLhaus (Abuse.ch)",
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, 20*time.Minute)
	c.JSON(http.StatusOK, result)
}

// ── MalwareBazaar (Abuse.ch) ─────────────────────────────────────────────

// GetMalwareBazaarRecent returns recent malware samples with ICS/OT tags.
func GetMalwareBazaarRecent(c *gin.Context) {
	const cacheKey = "malwarebazaar-recent"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	payload := map[string]any{"query": "get_recent", "selector": "100"}
	data, err := abusePost("https://mb-api.abuse.ch/api/v1/", payload)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	all := []any{}
	icsRelevant := []any{}
	if samples, ok := data["data"].([]any); ok {
		for _, s := range samples {
			m, ok := s.(map[string]any)
			if !ok {
				continue
			}
			all = append(all, m)
			tags := strings.ToLower(fmt.Sprint(m["tags"]))
			family := strings.ToLower(fmt.Sprint(m["signature"]))
			if isICSRelevant(tags+family) || isICSMalware(family) {
				icsRelevant = append(icsRelevant, m)
			}
		}
	}

	result := gin.H{
		"samples":      all,
		"ics_samples":  icsRelevant,
		"total":        len(all),
		"ics_total":    len(icsRelevant),
		"source":       "MalwareBazaar (Abuse.ch)",
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, 20*time.Minute)
	c.JSON(http.StatusOK, result)
}

// ── CISA ICS Advisories ───────────────────────────────────────────────────

// GetCISAAdvisories returns recent ICS-CERT advisories from CISA RSS.
func GetCISAAdvisories(c *gin.Context) {
	const cacheKey = "cisa-advisories"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	resp, err := httpGet("https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml")
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	type RSSItem struct {
		Title   string `xml:"title"`
		Link    string `xml:"link"`
		PubDate string `xml:"pubDate"`
		Desc    string `xml:"description"`
		GUID    string `xml:"guid"`
	}
	type RSS struct {
		Items []RSSItem `xml:"channel>item"`
	}

	body, _ := io.ReadAll(resp.Body)
	var feed RSS
	xml.Unmarshal(body, &feed)

	advisories := make([]map[string]any, 0, len(feed.Items))
	for _, item := range feed.Items {
		// Strip HTML tags from description
		desc := stripHTML(item.Desc)
		advisories = append(advisories, map[string]any{
			"title":    item.Title,
			"link":     item.Link,
			"pub_date": item.PubDate,
			"summary":  desc,
			"id":       item.GUID,
		})
	}

	result := gin.H{
		"advisories": advisories,
		"total":      len(advisories),
		"source":     "CISA ICS-CERT",
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, time.Hour)
	c.JSON(http.StatusOK, result)
}

// ── GreyNoise ─────────────────────────────────────────────────────────────

// GetGreyNoiseICS queries GreyNoise for ICS-scanning hosts (Modbus, S7, DNP3, BACnet).
func GetGreyNoiseICS(c *gin.Context) {
	const cacheKey = "greynoise-ics"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	apiKey := os.Getenv("GREYNOISE_API_KEY")
	if apiKey == "" {
		// Return curated static dataset when no key is present
		c.JSON(http.StatusOK, gin.H{
			"scanners":   staticGreyNoiseData(),
			"total":      len(staticGreyNoiseData()),
			"source":     "GreyNoise (static — set GREYNOISE_API_KEY for live data)",
			"live":       false,
			"fetched_at": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// GNQL query: ICS protocol scanners
	queries := []string{
		"tags:ICS+Scanning",
		"tags:Modbus+Scanner",
		"tags:DNP3+Scanner",
		"tags:S7+Scanner",
	}

	allData := []any{}
	for _, q := range queries {
		url := fmt.Sprintf("https://api.greynoise.io/v2/experimental/gnql?query=%s&size=50", q)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("key", apiKey)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()

		var raw map[string]any
		json.NewDecoder(resp.Body).Decode(&raw)
		if data, ok := raw["data"].([]any); ok {
			allData = append(allData, data...)
		}
	}

	result := gin.H{
		"scanners":   allData,
		"total":      len(allData),
		"source":     "GreyNoise",
		"live":       true,
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, 30*time.Minute)
	c.JSON(http.StatusOK, result)
}

// GetGreyNoiseIP checks a single IP against GreyNoise community API (free, no key needed).
func GetGreyNoiseIP(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip param required"})
		return
	}

	cacheKey := "greynoise-ip-" + ip
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	// Community API is free, no key required
	resp, err := httpGet("https://api.greynoise.io/v3/community/" + ip)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	cache.Default.Set(cacheKey, result, time.Hour)
	c.JSON(http.StatusOK, result)
}

// ── Shodan ────────────────────────────────────────────────────────────────

// GetShodanICS searches Shodan for internet-exposed ICS devices by protocol.
func GetShodanICS(c *gin.Context) {
	protocol := c.DefaultQuery("protocol", "modbus")

	cacheKey := "shodan-ics-" + protocol
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		c.JSON(http.StatusOK, gin.H{
			"matches":    staticShodanData(protocol),
			"total":      len(staticShodanData(protocol)),
			"protocol":   protocol,
			"source":     "Shodan (static — set SHODAN_API_KEY for live data)",
			"live":       false,
			"fetched_at": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	queries := map[string]string{
		"modbus":  "port:502",
		"s7":      "port:102 siemens",
		"dnp3":    "port:20000 dnp3",
		"bacnet":  "port:47808 bacnet",
		"enip":    "port:44818 enip",
		"iec104":  "port:2404 iec",
		"foxapi":  "port:1911 fox",
	}

	query, ok := queries[protocol]
	if !ok {
		query = "port:502" // default to Modbus
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&minify=true", apiKey, query)
	resp, err := httpGet(url)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var raw map[string]any
	json.NewDecoder(resp.Body).Decode(&raw)

	result := gin.H{
		"matches":    raw["matches"],
		"total":      raw["total"],
		"protocol":   protocol,
		"query":      query,
		"source":     "Shodan",
		"live":       true,
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
	}
	cache.Default.Set(cacheKey, result, time.Hour)
	c.JSON(http.StatusOK, result)
}

// GetThreatIntelSummary returns a combined summary from all intel sources for the dashboard.
func GetThreatIntelSummary(c *gin.Context) {
	const cacheKey = "intel-summary"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	summary := map[string]any{
		"sources": []map[string]any{
			{
				"name":        "ThreatFox",
				"description": "Active C2 servers and malware IOCs",
				"endpoint":    "/api/intel/threatfox",
				"free":        true,
				"key_required": false,
				"ics_focused": true,
				"update_freq": "15 min",
			},
			{
				"name":        "Feodo Tracker",
				"description": "Botnet C2 IP blocklist (Emotet, TrickBot, QakBot)",
				"endpoint":    "/api/intel/feodo",
				"free":        true,
				"key_required": false,
				"ics_focused": false,
				"update_freq": "30 min",
			},
			{
				"name":        "URLhaus",
				"description": "Malicious URL distribution sites",
				"endpoint":    "/api/intel/urlhaus",
				"free":        true,
				"key_required": false,
				"ics_focused": false,
				"update_freq": "20 min",
			},
			{
				"name":        "MalwareBazaar",
				"description": "Malware sample repository with ICS-tagged samples",
				"endpoint":    "/api/intel/malwarebazaar",
				"free":        true,
				"key_required": false,
				"ics_focused": true,
				"update_freq": "20 min",
			},
			{
				"name":        "CISA ICS-CERT",
				"description": "Official ICS security advisories",
				"endpoint":    "/api/intel/cisa-advisories",
				"free":        true,
				"key_required": false,
				"ics_focused": true,
				"update_freq": "1 hr",
			},
			{
				"name":        "GreyNoise",
				"description": "ICS protocol scanner detection and IP context",
				"endpoint":    "/api/intel/greynoise",
				"free":        true,
				"key_required": false,
				"live_key_env": "GREYNOISE_API_KEY",
				"ics_focused": true,
				"update_freq": "30 min",
			},
			{
				"name":        "Shodan",
				"description": "Internet-exposed ICS devices (Modbus, S7, DNP3, BACnet)",
				"endpoint":    "/api/intel/shodan",
				"free":        false,
				"key_required": true,
				"live_key_env": "SHODAN_API_KEY",
				"ics_focused": true,
				"update_freq": "1 hr",
			},
		},
		"configured_keys": map[string]bool{
			"GREYNOISE_API_KEY": os.Getenv("GREYNOISE_API_KEY") != "",
			"SHODAN_API_KEY":    os.Getenv("SHODAN_API_KEY") != "",
			"OTX_API_KEY":       os.Getenv("OTX_API_KEY") != "",
		},
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
	}

	cache.Default.Set(cacheKey, summary, 5*time.Minute)
	c.JSON(http.StatusOK, summary)
}

// ── Helpers ───────────────────────────────────────────────────────────────

func abusePost(url string, payload any) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CPS-Threat-Dashboard/2.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

var icsKeywordList = []string{
	"ics", "scada", "plc", "hmi", "modbus", "dnp3", "s7comm", "codesys",
	"triton", "industroyer", "crashoverride", "stuxnet", "blackenergy",
	"xenotime", "sandworm", "voltzite", "siemens", "rockwell", "schneider",
	"abb", "honeywell", "yokogawa", "ge", "emerson", "delta", "profinet",
	"ethernetip", "bacnet", "enip", "iec104", "opcua", "foxapi",
	"historian", "wonderware", "ignition", "factorytalk", "wincc",
}

var icsMalwareFamilies = []string{
	"triton", "trisis", "industroyer", "crashoverride", "stuxnet",
	"blackenergy", "havex", "irongate", "ekans", "snake", "megacortex",
	"caddywiper", "ousaban", "sandworm", "incontroller", "pipedream",
}

func isICSRelevant(text string) bool {
	for _, kw := range icsKeywordList {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

func isICSMalware(name string) bool {
	for _, fam := range icsMalwareFamilies {
		if strings.Contains(name, fam) {
			return true
		}
	}
	return false
}

func stripHTML(s string) string {
	inTag := false
	out := strings.Builder{}
	for _, r := range s {
		if r == '<' {
			inTag = true
		} else if r == '>' {
			inTag = false
		} else if !inTag {
			out.WriteRune(r)
		}
	}
	result := strings.TrimSpace(out.String())
	if len(result) > 400 {
		return result[:400] + "..."
	}
	return result
}

// staticGreyNoiseData returns curated ICS scanner data when no API key is set.
func staticGreyNoiseData() []map[string]any {
	return []map[string]any{
		{"ip": "198.20.70.114", "classification": "malicious", "name": "SHODAN", "tags": []string{"ICS Scanning", "Modbus Scanner"}, "country_code": "US", "last_seen": "2026-03-20"},
		{"ip": "80.82.77.33", "classification": "malicious", "name": "Shadowserver", "tags": []string{"ICS Scanning", "S7 Scanner"}, "country_code": "DE", "last_seen": "2026-03-21"},
		{"ip": "185.220.101.45", "classification": "malicious", "name": "Unknown", "tags": []string{"Tor Exit Node", "ICS Scanning"}, "country_code": "RU", "last_seen": "2026-03-19"},
		{"ip": "45.33.32.156", "classification": "malicious", "name": "NMAP Scanner", "tags": []string{"ICS Scanning", "DNP3 Scanner"}, "country_code": "US", "last_seen": "2026-03-18"},
		{"ip": "89.248.167.131", "classification": "malicious", "name": "Unknown ICS Probe", "tags": []string{"Modbus Scanner", "BACnet Scanner"}, "country_code": "NL", "last_seen": "2026-03-21"},
		{"ip": "71.6.135.131", "classification": "malicious", "name": "Censys", "tags": []string{"ICS Scanning"}, "country_code": "US", "last_seen": "2026-03-20"},
		{"ip": "5.188.86.125", "classification": "malicious", "name": "Unknown", "tags": []string{"ICS Scanning", "S7 Scanner"}, "country_code": "CN", "last_seen": "2026-03-17"},
		{"ip": "213.183.57.86", "classification": "malicious", "name": "Unknown APT Probe", "tags": []string{"ICS Scanning", "EtherNet/IP Scanner"}, "country_code": "RU", "last_seen": "2026-03-21"},
	}
}

// staticShodanData returns curated Shodan-style data when no API key is set.
func staticShodanData(protocol string) []map[string]any {
	base := []map[string]any{
		{"ip_str": "192.0.2.1", "port": 502, "protocol": "modbus", "org": "Example ISP", "country_code": "US", "product": "Schneider Electric Modicon", "vulns": []string{"CVE-2017-6032"}, "last_update": "2026-03-15"},
		{"ip_str": "192.0.2.2", "port": 102, "protocol": "s7", "org": "Industrial Corp", "country_code": "DE", "product": "Siemens S7-1200", "vulns": []string{"CVE-2022-38465"}, "last_update": "2026-03-18"},
		{"ip_str": "192.0.2.3", "port": 20000, "protocol": "dnp3", "org": "Utility Provider", "country_code": "UA", "product": "ABB RTU", "vulns": []string{}, "last_update": "2026-03-10"},
		{"ip_str": "192.0.2.4", "port": 47808, "protocol": "bacnet", "org": "Building Systems Inc", "country_code": "GB", "product": "Honeywell BACnet Controller", "vulns": []string{}, "last_update": "2026-03-19"},
		{"ip_str": "192.0.2.5", "port": 44818, "protocol": "enip", "org": "Factory Networks LLC", "country_code": "US", "product": "Rockwell Automation ControlLogix", "vulns": []string{"CVE-2021-22681"}, "last_update": "2026-03-20"},
	}
	filtered := []map[string]any{}
	for _, d := range base {
		if protocol == "all" || d["protocol"] == protocol {
			filtered = append(filtered, d)
		}
	}
	if len(filtered) == 0 {
		return base // return all if protocol not matched
	}
	return filtered
}

// ── Global IOC Search ──────────────────────────────────────────────────────

// GetIOCSearch fans out a single indicator query to ThreatFox, GreyNoise, and
// MalwareBazaar simultaneously and returns a unified result.
func GetIOCSearch(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q param required"})
		return
	}

	type result struct {
		Source string `json:"source"`
		Data   any    `json:"data"`
		Error  string `json:"error,omitempty"`
	}

	results := []result{}

	// ── ThreatFox search ───────────────────────────────────────────────────
	tfPayload := map[string]any{"query": "search_ioc", "search_term": q}
	tfData, err := abusePost("https://threatfox-api.abuse.ch/api/v1/", tfPayload)
	if err == nil {
		results = append(results, result{Source: "ThreatFox", Data: tfData})
	} else {
		results = append(results, result{Source: "ThreatFox", Error: err.Error()})
	}

	// ── GreyNoise community IP lookup (IPs only) ───────────────────────────
	if isLikelyIP(q) {
		gnResp, gnErr := httpGet(fmt.Sprintf("https://api.greynoise.io/v3/community/%s", q))
		if gnErr == nil {
			defer gnResp.Body.Close()
			var gnData map[string]any
			if json.NewDecoder(gnResp.Body).Decode(&gnData) == nil {
				results = append(results, result{Source: "GreyNoise", Data: gnData})
			}
		} else {
			results = append(results, result{Source: "GreyNoise", Error: gnErr.Error()})
		}

		// ── Feodo check ───────────────────────────────────────────────────
		feodoResults := checkFeodoIP(q)
		results = append(results, result{Source: "Feodo Tracker", Data: feodoResults})
	}

	// ── MalwareBazaar hash lookup ──────────────────────────────────────────
	if isLikelyHash(q) {
		mbPayload := map[string]any{"query": "get_info", "hash": q}
		mbData, mbErr := abusePost("https://mb-api.abuse.ch/api/v1/", mbPayload)
		if mbErr == nil {
			results = append(results, result{Source: "MalwareBazaar", Data: mbData})
		} else {
			results = append(results, result{Source: "MalwareBazaar", Error: mbErr.Error()})
		}
	}

	// ── CISA KEV check (CVE IDs) ───────────────────────────────────────────
	if strings.HasPrefix(strings.ToUpper(q), "CVE-") {
		kevMatch := checkKEV(q)
		results = append(results, result{Source: "CISA KEV", Data: kevMatch})
	}

	c.JSON(http.StatusOK, gin.H{
		"query":   q,
		"results": results,
		"count":   len(results),
	})
}

func isLikelyIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
	}
	return true
}

func isLikelyHash(s string) bool {
	l := len(s)
	return (l == 32 || l == 40 || l == 64) && isHex(s)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func checkFeodoIP(ip string) map[string]any {
	resp, err := httpGet("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
	if err != nil {
		return map[string]any{"found": false, "error": err.Error()}
	}
	defer resp.Body.Close()
	var blocklist []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&blocklist); err != nil {
		return map[string]any{"found": false}
	}
	for _, entry := range blocklist {
		if fmt.Sprint(entry["ip_address"]) == ip {
			return map[string]any{"found": true, "entry": entry}
		}
	}
	return map[string]any{"found": false, "checked": len(blocklist)}
}

func checkKEV(cveID string) map[string]any {
	resp, err := httpGet(kevURL)
	if err != nil {
		return map[string]any{"found": false, "error": err.Error()}
	}
	defer resp.Body.Close()
	var raw struct {
		Vulnerabilities []map[string]any `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return map[string]any{"found": false}
	}
	upper := strings.ToUpper(cveID)
	for _, v := range raw.Vulnerabilities {
		if strings.ToUpper(fmt.Sprint(v["cveID"])) == upper {
			return map[string]any{"found": true, "entry": v}
		}
	}
	return map[string]any{"found": false, "total_kev": len(raw.Vulnerabilities)}
}
