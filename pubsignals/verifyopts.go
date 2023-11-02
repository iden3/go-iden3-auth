package pubsignals

import "time"

var (
	DefaultAuthVerifyOpts  = VerifyConfig{AcceptedStateTransitionDelay: time.Minute * 5}
	DefaultProofVerifyOpts = VerifyConfig{AcceptedStateTransitionDelay: time.Hour,
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

// VerifyOpt sets options.
type VerifyOpt func(v *VerifyConfig)

// VerifyConfig verifiers options.
type VerifyConfig struct {
	// is the period of time that a revoked state remains valid.
	AcceptedStateTransitionDelay time.Duration
	AcceptedProofGenerationDelay time.Duration
}
