package state

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-iden3-auth/v2/cache"
	"github.com/stretchr/testify/require"
)

func newTestResolverWithCache(stateCache, rootCache cache.Cache[ResolvedState]) *ETHResolver {
	return &ETHResolver{
		stateResolveCache: stateCache,
		rootResolveCache:  rootCache,
		cfg: Config{
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
	require.NoError(t, err, "expected no error")
	require.True(t, result.Latest, "expected result to be marked as latest")
}

func TestGistResolve_UsesCacheIfPresent(t *testing.T) {
	mock := cache.NewInMemoryCache[ResolvedState](10, time.Minute)
	key := "123"
	expected := ResolvedState{Latest: true}
	mock.Set(key, expected)

	resolver := newTestResolverWithCache(nil, mock)

	result, err := resolver.ResolveGlobalRoot(context.Background(), big.NewInt(123))
	require.NoError(t, err, "expected no error")
	require.True(t, result.Latest, "expected result to be marked as latest")
}
