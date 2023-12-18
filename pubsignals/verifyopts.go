package pubsignals

import (
	"time"
)

var (
	defaultAuthVerifyOpts  = VerifyConfig{AcceptedStateTransitionDelay: time.Minute * 5, SupportSdOperator: false}
	defaultProofVerifyOpts = VerifyConfig{AcceptedStateTransitionDelay: time.Hour,
		AcceptedProofGenerationDelay: time.Hour * 24, SupportSdOperator: false}
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

// WithSupportSdOperator sets the flag of supporting SD operator (v3) or replacing it to EQ (v2).
func WithSupportSdOperator(supportSdOperator bool) VerifyOpt {
	return func(v *VerifyConfig) {
		v.SupportSdOperator = supportSdOperator
	}
}

// VerifyOpt sets options.
type VerifyOpt func(v *VerifyConfig)

// VerifyConfig verifiers options.
type VerifyConfig struct {
	// is the period of time that a revoked state remains valid.
	AcceptedStateTransitionDelay time.Duration
	AcceptedProofGenerationDelay time.Duration
	SupportSdOperator            bool
}

// ParamNameVerifierDID is a verifier did - specific  circuit param for V3, but can be utilized by other circuits
const ParamNameVerifierDID = "verifierDid"

// ParamNameNullifierSessionID is a nullifier session id - specific  circuit param for V3 to generate nullifier
const ParamNameNullifierSessionID = "nullifierSessionId"
