package state_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-iden3-auth/v2/cache"
	"github.com/iden3/go-iden3-auth/v2/state"
)

func TestResolve_UsesCacheIfPresent(t *testing.T) {
	mock := cache.NewInMemoryCache[state.ResolvedState](10, time.Minute)
	key := "1-2"
	expected := state.ResolvedState{Latest: true}
	mock.Set(key, expected)

	resolver := state.NewETHResolver("", "", &state.ResolverOptions{
		StateCacheOptions: &state.CacheOptions{
			Cache: mock,
		},
	})

	result, err := resolver.Resolve(context.Background(), big.NewInt(1), big.NewInt(2))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Latest != true {
		t.Errorf("expected to get cached result, got %+v", result)
	}
}

func TestGistResolve_UsesCacheIfPresent(t *testing.T) {
	mock := cache.NewInMemoryCache[state.ResolvedState](10, time.Minute)
	key := "123"
	expected := state.ResolvedState{Latest: true}
	mock.Set(key, expected)

	resolver := state.NewETHResolver("", "", &state.ResolverOptions{
		RootCacheOptions: &state.CacheOptions{
			Cache: mock,
		},
	})

	result, err := resolver.ResolveGlobalRoot(context.Background(), big.NewInt(123))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Latest != true {
		t.Errorf("expected to get cached result, got %+v", result)
	}
}
