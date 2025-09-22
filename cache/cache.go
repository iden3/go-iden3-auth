package cache

import (
	"time"

	"github.com/karlseguin/ccache/v3"
)

// Cache is a generic interface for a cache implementation.
type Cache[T any] interface {
	Get(key string) (T, bool)
	Set(key string, value T, opts ...SetOptions)
	Delete(key string)
	Clear()
	Len() int
}

// InMemoryCache is an in-memory cache implementation using ccache.
type InMemoryCache[T any] struct {
	cache      *ccache.Cache[T]
	defaultTTL time.Duration
}

// SetConfig holds the configuration for setting cache items.
type SetConfig struct {
	ttl time.Duration
}

// SetOptions is a function that modifies the SetConfig.
type SetOptions func(*SetConfig)

// WithTTL is an option for Set that allows specifying a custom TTL for the cache item.
func WithTTL(ttl time.Duration) SetOptions {
	return func(cfg *SetConfig) {
		cfg.ttl = ttl
	}
}

// NewInMemoryCache creates a new in-memory cache with the specified size and default TTL.
func NewInMemoryCache[T any](size int64, defaultTTL time.Duration) *InMemoryCache[T] {
	cache := ccache.New(ccache.Configure[T]().MaxSize(size))
	return &InMemoryCache[T]{
		cache:      cache,
		defaultTTL: defaultTTL,
	}
}

// Get retrieves an item from the cache by its key.
func (c *InMemoryCache[T]) Get(key string) (T, bool) {
	item := c.cache.Get(key)
	if item == nil || item.Expired() {
		var zero T
		return zero, false
	}
	return item.Value(), true
}

// Set adds an item to the cache with a specified key and value and optional ttl.
func (c *InMemoryCache[T]) Set(key string, value T, opts ...SetOptions) {
	cfg := SetConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	expire := c.defaultTTL
	if cfg.ttl > 0 {
		expire = cfg.ttl
	}
	c.cache.Set(key, value, expire)
}

// Delete removes an item from the cache by its key.
func (c *InMemoryCache[T]) Delete(key string) {
	c.cache.Delete(key)
}

// Clear removes all items from the cache.
func (c *InMemoryCache[T]) Clear() {
	c.cache.Clear()
}

// Len returns the number of items currently in the cache.
func (c *InMemoryCache[T]) Len() int {
	return c.cache.ItemCount()
}
