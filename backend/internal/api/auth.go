package api

import (
	"crypto/subtle"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// BasicAuth middleware — enabled when DASHBOARD_PASSWORD env var is set.
// Usage: set DASHBOARD_USER and DASHBOARD_PASSWORD in Railway env vars.
func BasicAuth() gin.HandlerFunc {
	user := os.Getenv("DASHBOARD_USER")
	pass := os.Getenv("DASHBOARD_PASSWORD")

	// If no password set, skip auth (local dev)
	if pass == "" {
		return func(c *gin.Context) { c.Next() }
	}
	if user == "" {
		user = "admin"
	}

	return gin.BasicAuth(gin.Accounts{user: pass})
}

// RateLimitAIBriefing blocks the AI briefing endpoint if no API key is configured,
// preventing accidental charges on public deployments.
func GuardAIEndpoints() gin.HandlerFunc {
	return func(c *gin.Context) {
		if os.Getenv("ANTHROPIC_API_KEY") == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "AI Briefing not configured on this deployment",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// secureCompare does constant-time string comparison to prevent timing attacks.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
