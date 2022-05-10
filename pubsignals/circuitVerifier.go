package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
)

// Verifier is interface for verification of public signals of zkp
type Verifier interface {
	VerifyQuery(ctx context.Context, query Query) error
	VerifyStates(ctx context.Context, opts VerificationOptions) error

	circuits.PubSignalsUnmarshaller
}
