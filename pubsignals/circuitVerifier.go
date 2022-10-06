package pubsignals

import (
	"context"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/state"
)

// StateResolver is a state resolver interface
type StateResolver interface {
	Resolve(ctx context.Context, id *big.Int, state *big.Int) (*state.ResolvedState, error)
}

// Verifier is interface for verification of public signals of zkp
type Verifier interface {
	VerifyQuery(ctx context.Context, query Query, schemaLoader loaders.SchemaLoader) error
	VerifyStates(ctx context.Context, resolver StateResolver) error

	IDOwnershipVerifier
	circuits.PubSignalsUnmarshaller
}

// IDOwnershipVerifier is an interface for verification of sender id ownership
type IDOwnershipVerifier interface {
	VerifyIDOwnership(userIdentifier string, challenge *big.Int) error
}
