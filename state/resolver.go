package state

import (
	"context"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

// ETHResolver resolver for eth blockchains
type ETHResolver struct {
	RPCUrl   string
	Contract string
}

// Resolve returns Resolved state from blockchain
func (r ETHResolver) Resolve(ctx context.Context, id, state *big.Int) (*ResolvedState, error) {
	client, err := ethclient.Dial(r.RPCUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return Resolve(ctx, client, r.Contract, id, state)
}
