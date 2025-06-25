package state

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/go-iden3-auth/v2/cache"
	"github.com/iden3/go-iden3-auth/v2/constants"
)

// CacheOptions holds caching behavior configuration
type CacheOptions struct {
	// TTL for latest (not replaced) entries
	NotReplacedTTL time.Duration
	// TTL for historical (replaced) entries
	ReplacedTTL time.Duration
	// Maximum number of entries in the cache
	MaxSize int64
	// Optional custom cache implementation
	Cache cache.ICache[ResolvedState]
}

// ResolverOptions is the full config for ETHResolver
type ResolverOptions struct {
	// Caching options for state resolution
	StateCacheOptions *CacheOptions
	// Caching options for GIST root resolution
	RootCacheOptions *CacheOptions
}

// ETHResolver resolver for eth blockchains
type ETHResolver struct {
	RPCUrl            string
	ContractAddress   common.Address
	ethClient         *ethclient.Client
	stateCaller       *abi.StateCaller
	opts              ResolverOptions
	stateResolveCache cache.ICache[ResolvedState]
	rootResolveCache  cache.ICache[ResolvedState]
}

// NewETHResolver create ETH resolver for state.
func NewETHResolver(url, contract string, opts *ResolverOptions) *ETHResolver {
	ethClient, err := ethclient.Dial(url)
	if err != nil {
		panic(fmt.Sprintf("failed to connect to RPC: %v", err))
	}

	stateCaller, err := abi.NewStateCaller(common.HexToAddress(contract), ethClient)
	if err != nil {
		panic(fmt.Sprintf("failed to create state caller: %v", err))
	}

	if opts == nil {
		opts = &ResolverOptions{}
	}

	// ---- State Cache Options ----
	stateOpts := &CacheOptions{}
	if opts.StateCacheOptions != nil {
		stateOpts = opts.StateCacheOptions
	}
	if stateOpts.NotReplacedTTL == 0 {
		stateOpts.NotReplacedTTL = constants.StateCacheOptions.NotReplacedTTL
	}
	if stateOpts.ReplacedTTL == 0 {
		stateOpts.ReplacedTTL = constants.StateCacheOptions.ReplacedTTL
	}
	if stateOpts.MaxSize == 0 {
		stateOpts.MaxSize = constants.DefaultCacheMaxSize
	}
	var stateCache cache.ICache[ResolvedState]
	if stateOpts.Cache != nil {
		stateCache = stateOpts.Cache
	} else {
		stateCache = cache.NewInMemoryCache[ResolvedState](stateOpts.MaxSize, stateOpts.ReplacedTTL)
	}

	// ---- Root Cache Options ----
	rootOpts := &CacheOptions{}
	if opts.RootCacheOptions != nil {
		rootOpts = opts.RootCacheOptions
	}
	if rootOpts.NotReplacedTTL == 0 {
		rootOpts.NotReplacedTTL = constants.GistRootCacheOptions.NotReplacedTTL
	}
	if rootOpts.ReplacedTTL == 0 {
		rootOpts.ReplacedTTL = constants.GistRootCacheOptions.ReplacedTTL
	}
	if rootOpts.MaxSize == 0 {
		rootOpts.MaxSize = constants.DefaultCacheMaxSize
	}

	var rootCache cache.ICache[ResolvedState]
	if rootOpts.Cache != nil {
		rootCache = rootOpts.Cache
	} else {
		rootCache = cache.NewInMemoryCache[ResolvedState](rootOpts.MaxSize, rootOpts.ReplacedTTL)
	}

	opts.StateCacheOptions = stateOpts
	opts.RootCacheOptions = rootOpts

	return &ETHResolver{
		RPCUrl:            url,
		ContractAddress:   common.HexToAddress(contract),
		stateCaller:       stateCaller,
		ethClient:         ethClient,
		opts:              *opts,
		stateResolveCache: stateCache,
		rootResolveCache:  rootCache,
	}
}

// Resolve returns Resolved state from blockchain
func (r ETHResolver) Resolve(ctx context.Context, id, state *big.Int) (*ResolvedState, error) {
	cacheKey := r.getCacheKey(id, state)
	if cached, ok := r.stateResolveCache.Get(cacheKey); ok {
		return &cached, nil
	}
	resolved, err := Resolve(ctx, r.stateCaller, id, state)
	if err != nil {
		return nil, err
	}
	// Store resolved state in cache
	ttl := r.opts.StateCacheOptions.ReplacedTTL
	if resolved.TransitionTimestamp == 0 {
		ttl = r.opts.StateCacheOptions.NotReplacedTTL
	}
	r.stateResolveCache.Set(cacheKey, *resolved, ttl)

	return resolved, nil
}

// ResolveGlobalRoot returns Resolved global state from blockchain
func (r ETHResolver) ResolveGlobalRoot(ctx context.Context, state *big.Int) (*ResolvedState, error) {
	cacheKey := r.getRootCacheKey(state)
	if cached, ok := r.rootResolveCache.Get(cacheKey); ok {
		return &cached, nil
	}

	resolved, err := ResolveGlobalRoot(ctx, r.stateCaller, state)
	if err != nil {
		return nil, err
	}
	// Store resolved state in cache
	ttl := r.opts.RootCacheOptions.ReplacedTTL
	if resolved.TransitionTimestamp == 0 {
		ttl = r.opts.RootCacheOptions.NotReplacedTTL
	}
	r.rootResolveCache.Set(cacheKey, *resolved, ttl)
	return resolved, nil
}

func (r ETHResolver) getCacheKey(id, state *big.Int) string {
	return fmt.Sprintf("%s-%s", id.String(), state.String())
}

func (r ETHResolver) getRootCacheKey(root *big.Int) string {
	return root.String()
}

// Close closes the ETHResolver and its underlying client.
func (r *ETHResolver) Close() error {
	if r.ethClient != nil {
		r.ethClient.Close()
	}
	return nil
}
