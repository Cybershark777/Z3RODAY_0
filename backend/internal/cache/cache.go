package cache

import (
	"sync"
	"time"
)

type entry struct {
	data      any
	expiresAt time.Time
}

// Cache is a simple thread-safe TTL in-memory store.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
}

var Default = &Cache{entries: make(map[string]entry)}

func (c *Cache) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.data, true
}

func (c *Cache) Set(key string, data any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry{data: data, expiresAt: time.Now().Add(ttl)}
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Purge removes all expired entries.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// StartJanitor runs a background goroutine that purges expired entries.
func (c *Cache) StartJanitor(interval time.Duration) {
	go func() {
		for range time.Tick(interval) {
			c.Purge()
		}
	}()
}
