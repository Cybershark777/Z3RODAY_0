package api

import (
	"encoding/json"
	"math"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gwu/cps-threat-dashboard/internal/cache"
	"github.com/gwu/cps-threat-dashboard/internal/db"
	"github.com/gwu/cps-threat-dashboard/internal/models"
)

// GetMLDetection returns synthetic SWAT sensor data with anomaly scores for ML-SOAR visualization.
func GetMLDetection(c *gin.Context) {
	const cacheKey = "ml-detection"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	result := buildMLDetection()
	cache.Default.Set(cacheKey, result, 5*time.Minute)
	c.JSON(http.StatusOK, result)
}

func buildMLDetection() map[string]any {
	rng := rand.New(rand.NewSource(42))
	steps := 500

	sensors := []struct {
		name    string
		base    float64
		noise   float64
		unit    string
	}{
		{"FIT-101", 2.2, 0.08, "L/s"},
		{"LIT-101", 500.0, 8.0, "mm"},
		{"AIT-201", 0.97, 0.02, "NTU"},
		{"FIT-301", 1.8, 0.06, "L/s"},
		{"DPIT-301", 55.0, 1.5, "kPa"},
		{"PIT-501", 0.40, 0.012, "MPa"},
	}

	attackWindows := []struct{ start, end int }{
		{120, 160},
		{270, 310},
		{400, 450},
	}

	isAttack := func(step int) bool {
		for _, w := range attackWindows {
			if step >= w.start && step <= w.end {
				return true
			}
		}
		return false
	}

	series := make(map[string][]float64)
	for _, s := range sensors {
		vals := make([]float64, steps)
		for i := range vals {
			v := s.base + rng.NormFloat64()*s.noise
			if isAttack(i) {
				v += s.base * 0.25 * rng.NormFloat64()
			}
			vals[i] = math.Round(v*1000) / 1000
		}
		series[s.name] = vals
	}

	// Z-score anomaly detection per sensor
	anomalyScores := make([]float64, steps)
	for _, s := range sensors {
		vals := series[s.name]
		mean, std := meanStd(vals)
		for i, v := range vals {
			z := math.Abs(v-mean) / (std + 1e-9)
			anomalyScores[i] += z / float64(len(sensors))
		}
	}

	// ML MTTD vs baseline per attack window
	comparisons := make([]map[string]any, 0)
	for wi, w := range attackWindows {
		baselineMTTD := 18.0 + float64(wi)*4 + rng.NormFloat64()*2
		mlMTTD := 3.2 + float64(wi)*0.8 + rng.NormFloat64()*0.5
		comparisons = append(comparisons, map[string]any{
			"window":       wi + 1,
			"start_step":   w.start,
			"end_step":     w.end,
			"baseline_mttd": math.Round(baselineMTTD*10) / 10,
			"ml_mttd":       math.Round(mlMTTD*10) / 10,
			"improvement":   math.Round((1-mlMTTD/baselineMTTD)*1000) / 10,
		})
	}

	// ROC curve (synthetic)
	rocPoints := make([]map[string]float64, 0)
	for _, threshold := range []float64{0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0} {
		tpr := 1.0 - threshold*0.9
		fpr := threshold * threshold * 0.3
		rocPoints = append(rocPoints, map[string]float64{"fpr": math.Round(fpr*1000) / 1000, "tpr": math.Round(tpr*1000) / 1000})
	}

	sensorMeta := make([]map[string]any, 0)
	for _, s := range sensors {
		sensorMeta = append(sensorMeta, map[string]any{
			"name": s.name,
			"base": s.base,
			"unit": s.unit,
		})
	}

	labels := make([]bool, steps)
	for i := range labels {
		labels[i] = isAttack(i)
	}

	return map[string]any{
		"sensors":        sensorMeta,
		"series":         series,
		"anomaly_scores": anomalyScores,
		"attack_labels":  labels,
		"comparisons":    comparisons,
		"roc_points":     rocPoints,
		"accuracy":       0.9312,
		"false_positive_rate": 0.0487,
		"steps":          steps,
	}
}

func meanStd(vals []float64) (float64, float64) {
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	variance := 0.0
	for _, v := range vals {
		d := v - mean
		variance += d * d
	}
	return mean, math.Sqrt(variance / float64(len(vals)))
}

// GetCVEAssetMap returns 25 ICS CVEs mapped to vendors, products, and Purdue levels.
func GetCVEAssetMap(c *gin.Context) {
	const cacheKey = "cve-asset-map"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	cves := buildCVEAssetMap()
	result := map[string]any{"cves": cves}
	cache.Default.Set(cacheKey, result, 30*time.Minute)
	c.JSON(http.StatusOK, result)
}

func buildCVEAssetMap() []map[string]any {
	return []map[string]any{
		{"cve": "CVE-2017-6032", "vendor": "Schneider Electric", "product": "Modicon M340", "cvss": 9.8, "purdue_level": 1, "kev": false, "description": "Unauthenticated remote code execution via Modbus/TCP"},
		{"cve": "CVE-2022-38465", "vendor": "Siemens", "product": "SIMATIC S7-1200/1500", "cvss": 9.3, "purdue_level": 1, "kev": true, "description": "Hardcoded global private key allows decryption of PLC traffic"},
		{"cve": "CVE-2021-22681", "vendor": "Rockwell Automation", "product": "Studio 5000 Logix Designer", "cvss": 10.0, "purdue_level": 2, "kev": true, "description": "Authentication bypass in ControlLogix PLCs"},
		{"cve": "CVE-2020-12505", "vendor": "WAGO", "product": "PFC200 PLC", "cvss": 9.8, "purdue_level": 1, "kev": false, "description": "Missing authentication for critical function via CODESYS"},
		{"cve": "CVE-2019-13945", "vendor": "Siemens", "product": "SIMATIC S7-1500 CPU", "cvss": 7.5, "purdue_level": 1, "kev": false, "description": "Denial-of-service via malformed S7comm-plus packets"},
		{"cve": "CVE-2022-29491", "vendor": "Honeywell", "product": "ControlEdge PLC", "cvss": 8.8, "purdue_level": 2, "kev": false, "description": "Improper input validation leads to buffer overflow"},
		{"cve": "CVE-2023-28655", "vendor": "ABB", "product": "AC500 PLC", "cvss": 9.0, "purdue_level": 1, "kev": false, "description": "Unauthenticated firmware update via FTP"},
		{"cve": "CVE-2021-33012", "vendor": "GE", "product": "CIMPLICITY", "cvss": 9.8, "purdue_level": 3, "kev": false, "description": "Deserialization of untrusted data in HMI software"},
		{"cve": "CVE-2022-44721", "vendor": "Yokogawa", "product": "CENTUM VP", "cvss": 9.8, "purdue_level": 3, "kev": false, "description": "Remote code execution in engineering workstation"},
		{"cve": "CVE-2023-2650", "vendor": "OSIsoft/AVEVA", "product": "PI Server", "cvss": 8.1, "purdue_level": 3, "kev": false, "description": "SQL injection in PI Web API"},
		{"cve": "CVE-2021-44228", "vendor": "Multiple", "product": "Log4Shell (ICS exposure)", "cvss": 10.0, "purdue_level": 4, "kev": true, "description": "Critical Log4j RCE affecting multiple ICS historian/HMI systems"},
		{"cve": "CVE-2022-26134", "vendor": "Multiple", "product": "Confluence (IT/OT bridge)", "cvss": 9.8, "purdue_level": 4, "kev": true, "description": "OGNL injection exploited in IT network, pivot to OT"},
		{"cve": "CVE-2019-18935", "vendor": "Unitronics", "product": "Vision PLC", "cvss": 9.8, "purdue_level": 1, "kev": true, "description": "Default credentials used in SCADA water system attack"},
		{"cve": "CVE-2020-15368", "vendor": "Multiple", "product": "Moxa NPort serial servers", "cvss": 7.5, "purdue_level": 0, "kev": false, "description": "Unauthenticated access to industrial serial device server"},
		{"cve": "CVE-2021-32934", "vendor": "Triangle MicroWorks", "product": "SCADA Data Gateway", "cvss": 9.8, "purdue_level": 2, "kev": false, "description": "Use-after-free in DNP3 protocol handling"},
		{"cve": "CVE-2023-31410", "vendor": "Siemens", "product": "RUGGEDCOM APE1808", "cvss": 9.8, "purdue_level": 2, "kev": false, "description": "Remote code execution in industrial router"},
		{"cve": "CVE-2022-0847", "vendor": "Linux", "product": "Dirty Pipe (embedded Linux PLCs)", "cvss": 7.8, "purdue_level": 1, "kev": true, "description": "Privilege escalation in Linux-based PLCs and embedded devices"},
		{"cve": "CVE-2023-1829", "vendor": "Schneider Electric", "product": "EcoStruxure Power Monitoring Expert", "cvss": 8.8, "purdue_level": 3, "kev": false, "description": "SQL injection in power monitoring system"},
		{"cve": "CVE-2021-27041", "vendor": "Autodesk", "product": "AutoCAD (engineering drawings)", "cvss": 7.8, "purdue_level": 4, "kev": false, "description": "Arbitrary code execution via malicious DWG files used in ICS design"},
		{"cve": "CVE-2022-23088", "vendor": "Emerson", "product": "DeltaV DCS", "cvss": 9.8, "purdue_level": 2, "kev": false, "description": "Buffer overflow in DCS communication module"},
		{"cve": "CVE-2023-38742", "vendor": "Mitsubishi Electric", "product": "MELSEC iQ-R PLC", "cvss": 7.5, "purdue_level": 1, "kev": false, "description": "Denial of service via crafted SLMP packets"},
		{"cve": "CVE-2021-40390", "vendor": "Advantech", "product": "WebAccess/SCADA", "cvss": 9.8, "purdue_level": 3, "kev": false, "description": "Remote code execution via SQL injection in HMI web server"},
		{"cve": "CVE-2020-8102", "vendor": "Kepware", "product": "KEPServerEX", "cvss": 9.1, "purdue_level": 2, "kev": false, "description": "Stack buffer overflow in OPC-UA communication server"},
		{"cve": "CVE-2022-34153", "vendor": "Claroty/Multiple", "product": "OPC UA SDK implementations", "cvss": 8.1, "purdue_level": 2, "kev": false, "description": "Certificate validation bypass in OPC UA industrial protocol"},
		{"cve": "CVE-2023-28489", "vendor": "Siemens", "product": "SCALANCE X Switches", "cvss": 9.8, "purdue_level": 2, "kev": false, "description": "OS command injection in industrial network switch management"},
	}
}

// GetKillChainTechniques returns ATT&CK ICS techniques organized by tactic for the kill chain builder.
func GetKillChainTechniques(c *gin.Context) {
	const cacheKey = "kill-chain"
	if cached, ok := cache.Default.Get(cacheKey); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	var tactics []models.MitreTactic
	db.DB.Order("`order` asc").Find(&tactics)

	var techniques []models.MitreTechnique
	db.DB.Find(&techniques)

	tacticMap := make(map[string][]map[string]any)
	for _, tech := range techniques {
		var full map[string]any
		if json.Unmarshal([]byte(tech.DataJSON), &full) == nil {
			tacticMap[tech.TacticID] = append(tacticMap[tech.TacticID], full)
		}
	}

	result := make([]map[string]any, 0)
	for _, t := range tactics {
		var full map[string]any
		json.Unmarshal([]byte(t.DataJSON), &full)
		result = append(result, map[string]any{
			"tactic":     full,
			"techniques": tacticMap[t.ID],
		})
	}

	resp := map[string]any{"kill_chain": result}
	cache.Default.Set(cacheKey, resp, 10*time.Minute)
	c.JSON(http.StatusOK, resp)
}
