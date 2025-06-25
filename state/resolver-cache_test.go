package state

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-iden3-auth/v2/cache"
)

func newTestResolverWithCache(stateCache, rootCache cache.ICache[ResolvedState]) *ETHResolver {
	return &ETHResolver{
		stateResolveCache: stateCache,
		rootResolveCache:  rootCache,
		opts: ResolverOptions{
			StateCacheOptions: &CacheOptions{
				Cache: stateCache,
			},
			RootCacheOptions: &CacheOptions{
				Cache: rootCache,
			},
		},
	}
}

func TestResolve_UsesCacheIfPresent(t *testing.T) {
	mock := cache.NewInMemoryCache[ResolvedState](10, time.Minute)
	key := "1-2"
	expected := ResolvedState{Latest: true}
	mock.Set(key, expected)

	resolver := newTestResolverWithCache(mock, nil)

	result, err := resolver.Resolve(context.Background(), big.NewInt(1), big.NewInt(2))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Latest != true {
		t.Errorf("expected to get cached result, got %+v", result)
	}
}

func TestGistResolve_UsesCacheIfPresent(t *testing.T) {
	mock := cache.NewInMemoryCache[ResolvedState](10, time.Minute)
	key := "123"
	expected := ResolvedState{Latest: true}
	mock.Set(key, expected)

	resolver := newTestResolverWithCache(nil, mock)

	result, err := resolver.ResolveGlobalRoot(context.Background(), big.NewInt(123))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Latest != true {
		t.Errorf("expected to get cached result, got %+v", result)
	}
}
