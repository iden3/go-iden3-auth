package cache

import (
	"time"

	"github.com/karlseguin/ccache/v3"
)

// ICache is a generic interface for a cache implementation.
type ICache[T any] interface {
	Get(key string) (T, bool)
	Set(key string, value T, ttl ...time.Duration)
	Delete(key string)
	Clear()
	Len() int
}

type inMemoryCache[T any] struct {
	cache      *ccache.Cache[T]
	defaultTTL time.Duration
}

// NewInMemoryCache creates a new in-memory cache with the specified size and default TTL.
func NewInMemoryCache[T any](size int64, defaultTTL time.Duration) ICache[T] {
	cache := ccache.New(ccache.Configure[T]().MaxSize(size))
	return &inMemoryCache[T]{
		cache:      cache,
		defaultTTL: defaultTTL,
	}
}

// Get retrieves an item from the cache by its key.
func (c *inMemoryCache[T]) Get(key string) (T, bool) {
	item := c.cache.Get(key)
	if item == nil || item.Expired() {
		var zero T
		return zero, false
	}
	return item.Value(), true
}

// Set adds an item to the cache with a specified key and value and optional ttl.
func (c *inMemoryCache[T]) Set(key string, value T, ttl ...time.Duration) {
	expire := c.defaultTTL
	if len(ttl) > 0 && ttl[0] > 0 {
		expire = ttl[0]
	}
	c.cache.Set(key, value, expire)
}

// Delete removes an item from the cache by its key.
func (c *inMemoryCache[T]) Delete(key string) {
	c.cache.Delete(key)
}

// Clear removes all items from the cache.
func (c *inMemoryCache[T]) Clear() {
	c.cache.Clear()
}

// Len returns the number of items currently in the cache.
func (c *inMemoryCache[T]) Len() int {
	return c.cache.ItemCount()
}
