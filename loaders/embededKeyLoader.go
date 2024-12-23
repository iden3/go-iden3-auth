package loaders

import (
	"embed"
	"fmt"
	"log/slog"
	"sync"

	"github.com/iden3/go-circuits/v2"
)

//go:embed keys/*.json
var defaultKeys embed.FS

// EmbeddedKeyLoader load keys from embedded FS or filesystem.
// Filesystem has priority if keyLoader specified.
type EmbeddedKeyLoader struct {
	keyLoader VerificationKeyLoader
	cache     map[circuits.CircuitID][]byte
	cacheMu   sync.RWMutex
	useCache  bool
}

// NewEmbeddedKeyLoader creates a new loader with embedded keys
// By default, it uses embedded keys with caching enabled
// Use options to customize behavior:
//   - WithKeyLoader to set custom loader
//   - WithCacheDisabled to disable caching
//
// Example:
// Default configuration (embedded keys and enabled cache):
//
//	loader := NewEmbeddedKeyLoader()
//
// Custom filesystem loader:
//
//	fsLoader := &FSKeyLoader{Dir: "/path/to/keys"}
//	loader := NewEmbeddedKeyLoader(WithKeyLoader(fsLoader))
//
// Disabled cache:
//
//	loader := NewEmbeddedKeyLoader(WithCacheDisabled())
func NewEmbeddedKeyLoader(opts ...Option) *EmbeddedKeyLoader {
	loader := &EmbeddedKeyLoader{
		useCache: true, // enabled by default
		cache:    make(map[circuits.CircuitID][]byte),
	}

	// Apply options
	for _, opt := range opts {
		opt(loader)
	}

	return loader
}

// Option defines functional option for configuring EmbeddedKeyLoader
type Option func(*EmbeddedKeyLoader)

// WithKeyLoader sets a custom primary loader that will be tried before falling back to embedded keys
func WithKeyLoader(loader VerificationKeyLoader) Option {
	return func(e *EmbeddedKeyLoader) {
		e.keyLoader = loader
	}
}

// WithCacheDisabled disables caching of loaded keys
func WithCacheDisabled() Option {
	return func(e *EmbeddedKeyLoader) {
		e.useCache = false
		e.cache = nil
	}
}

// Load attempts to load keys in the following order:
// 1. From cache if enabled and available
// 2. From keyLoader loader if provided
// 3. From embedded default keys
func (e *EmbeddedKeyLoader) Load(id circuits.CircuitID) ([]byte, error) {
	// Try cache if enabled
	if e.useCache {
		if key := e.getFromCache(id); key != nil {
			return key, nil
		}
	}

	// Try keyLoader loader if provided
	if e.keyLoader != nil {
		key, err := e.keyLoader.Load(id)
		if err == nil {
			if e.useCache {
				e.storeInCache(id, key)
			}
			return key, nil
		}
		slog.Warn("failed to load key from custom loader", "circuit_id", id, "error", err)
	}

	//  Embedded keys
	key, err := defaultKeys.ReadFile(fmt.Sprintf("keys/%v.json", id))
	if err != nil {
		return nil, fmt.Errorf("failed to load default key: %w", err)
	}

	if e.useCache {
		e.storeInCache(id, key)
	}
	return key, nil
}

// getFromCache returns key from cache if available
func (e *EmbeddedKeyLoader) getFromCache(id circuits.CircuitID) []byte {
	e.cacheMu.RLock()
	defer e.cacheMu.RUnlock()
	return e.cache[id]
}

// storeInCache stores key in cache
func (e *EmbeddedKeyLoader) storeInCache(id circuits.CircuitID, key []byte) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.cache[id] = key
}
