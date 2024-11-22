package pubsignals

import (
	"time"
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

// WithAllowExpiredMessages sets the allow expired messages option.
func WithAllowExpiredMessages(allowExpiredMessages bool) VerifyOpt {
	return func(v *VerifyConfig) {
		v.AllowExpiredMessages = &allowExpiredMessages
	}
}

// VerifyOpt sets options.
type VerifyOpt func(v *VerifyConfig)

// VerifyConfig verifiers options.
type VerifyConfig struct {
	// is the period of time that a revoked state remains valid.
	AcceptedStateTransitionDelay time.Duration
	AcceptedProofGenerationDelay time.Duration
	AllowExpiredMessages         *bool
}

// ParamNameVerifierDID is a verifier did - specific  circuit param for V3, but can be utilized by other circuits
const ParamNameVerifierDID = "verifierDid"

// ParamNameNullifierSessionID is a nullifier session id - specific  circuit param for V3 to generate nullifier
const ParamNameNullifierSessionID = "nullifierSessionId"
