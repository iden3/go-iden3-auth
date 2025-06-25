package constants

import "time"

const (
	// DefaultCacheMaxSize is the default maximum size for caches.
	DefaultCacheMaxSize int64 = 10_000
	// AcceptedProofGenerationDelay is the accepted delay of the proof generation.
	AcceptedProofGenerationDelay = time.Hour * 24 // 24 hours
	// AcceptedStateTransitionDelay is the accepted delay of state transition.
	AcceptedStateTransitionDelay = time.Hour // 1 hour
	// AuthAcceptedStateTransitionDelay is the accepted delay of state transition for auth circuit.
	AuthAcceptedStateTransitionDelay = 5 * time.Minute // 5 minutes
)

var (
	// StateCacheOptions defines the TTL options for state cache entries.
	StateCacheOptions = CacheTTLOptions{
		NotReplacedTTL: AcceptedStateTransitionDelay / 2, // 30 minutes
		ReplacedTTL:    AcceptedStateTransitionDelay,     // 1 hour
	}

	// GistRootCacheOptions defines the TTL options for GIST root cache entries.
	GistRootCacheOptions = CacheTTLOptions{
		NotReplacedTTL: AuthAcceptedStateTransitionDelay / 2, // 2.5 minutes
		ReplacedTTL:    AuthAcceptedStateTransitionDelay,     // 5 minutes
	}
)

// CacheTTLOptions defines the TTL options for cache entries.
type CacheTTLOptions struct {
	NotReplacedTTL time.Duration
	ReplacedTTL    time.Duration
}
