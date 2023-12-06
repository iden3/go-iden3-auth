package pubsignals

import (
	"math/big"
	"time"

	"github.com/iden3/go-iden3-core/v2/w3c"
)

var (
	defaultAuthVerifyOpts  = VerifyConfig{AcceptedStateTransitionDelay: time.Minute * 5}
	defaultProofVerifyOpts = VerifyConfig{AcceptedStateTransitionDelay: time.Hour,
		AcceptedProofGenerationDelay: time.Hour * 24}
)

// WithAcceptedStateTransitionDelay sets the delay of the revoked state.
func WithAcceptedStateTransitionDelay(duration time.Duration) VerifyOpt {
	return func(v *VerifyConfig) {
		v.AcceptedStateTransitionDelay = duration
	}
}

// WithAcceptedProofGenerationDelay sets the delay of the proof generation.
func WithAcceptedProofGenerationDelay(duration time.Duration) VerifyOpt {
	return func(v *VerifyConfig) {
		v.AcceptedProofGenerationDelay = duration
	}
}

// WithVerifierDID sets verifier to request
func WithVerifierDID(did *w3c.DID) VerifyOpt {
	return func(v *VerifyConfig) {
		v.VerifierDID = did
	}
}

// WithNullifierSessionID sets nullifierSessionID to request
func WithNullifierSessionID(nullifierSessionID *big.Int) VerifyOpt {
	return func(v *VerifyConfig) {
		v.NullifierSessionID = nullifierSessionID
	}
}

// VerifyOpt sets options.
type VerifyOpt func(v *VerifyConfig)

// VerifyConfig verifiers options.
type VerifyConfig struct {
	// is the period of time that a revoked state remains valid.
	AcceptedStateTransitionDelay time.Duration
	AcceptedProofGenerationDelay time.Duration
	VerifierDID                  *w3c.DID
	NullifierSessionID           *big.Int
}
