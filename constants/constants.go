package constants

import "time"

const (
	DefaultCacheMaxSize              int64 = 10_000
	AcceptedProofGenerationDelay           = time.Hour * 24  // 24 hours
	AcceptedStateTransitionDelay           = time.Hour       // 1 hour
	AuthAcceptedStateTransitionDelay       = 5 * time.Minute // 5 minutes
)

var (
	StateCacheOptions = CacheTTLOptions{
		NotReplacedTTL: AcceptedStateTransitionDelay / 2, // 30 minutes
		ReplacedTTL:    AcceptedStateTransitionDelay,     // 1 hour
	}

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
