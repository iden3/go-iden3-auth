package state

import (
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

// ETHResolver resolver for eth blockchains
type ETHResolver struct {
	RPCUrl          string
	ContractAddress common.Address
}

func NewETHResolver(url, contract string) *ETHResolver {
	return &ETHResolver{
		RPCUrl:          url,
		ContractAddress: common.HexToAddress(contract),
	}
}

// Resolve returns Resolved state from blockchain
func (r ETHResolver) Resolve(ctx context.Context, id, state *big.Int) (*ResolvedState, error) {
	client, err := ethclient.Dial(r.RPCUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	getter, err := NewStateCaller(r.ContractAddress, client)
	if err != nil {
		return nil, err
	}
	return Resolve(ctx, getter, id, state)
}

// ResolveGlobalRoot returns Resolved global state from blockchain
func (r ETHResolver) ResolveGlobalRoot(ctx context.Context, state *big.Int) (*ResolvedState, error) {
	client, err := ethclient.Dial(r.RPCUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	getter, err := NewStateCaller(r.ContractAddress, client)
	if err != nil {
		return nil, err
	}
	return ResolveGlobalRoot(ctx, getter, state)
}
