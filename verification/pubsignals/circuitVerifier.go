package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
)

type Verifier interface {
	VerifyQuery(ctx context.Context, query Query) error
	VerifyStates(ctx context.Context, opts VerificationOptions) error

	circuits.PubSignalsUnmarshaller
}
