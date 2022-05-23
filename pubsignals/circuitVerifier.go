package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/state"
	"math/big"
)

// StateResolver is a state resolver interface
type StateResolver interface {
	Resolve(ctx context.Context, id *big.Int, state *big.Int) (*state.ResolvedState, error)
}

// Verifier is interface for verification of public signals of zkp
type Verifier interface {
	VerifyQuery(ctx context.Context, query Query, schemaLoader loaders.SchemaLoader) error
	VerifyStates(ctx context.Context, resolver StateResolver) error

	circuits.PubSignalsUnmarshaller
}
