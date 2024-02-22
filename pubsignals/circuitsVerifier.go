package pubsignals

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/piprate/json-gold/ld"
)

// StateResolver is a state resolver interface
type StateResolver interface {
	Resolve(ctx context.Context, id *big.Int, state *big.Int) (*state.ResolvedState, error)
	ResolveGlobalRoot(ctx context.Context, state *big.Int) (*state.ResolvedState, error)
}

// Verifier is interface for verification of public signals of zkp
type Verifier interface {
	VerifyQuery(ctx context.Context, query Query, schemaLoader ld.DocumentLoader, verifiablePresentation json.RawMessage, circuitParams map[string]interface{}, opts ...VerifyOpt) (CircuitVerificationResult, error)
	VerifyStates(ctx context.Context, resolvers map[string]StateResolver, opts ...VerifyOpt) error
	VerifyIDOwnership(userIdentifier string, challenge *big.Int) error

	circuits.PubSignalsUnmarshaller
}
