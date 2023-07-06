package pubsignals

import "time"

var (
	defaultAuthVerifyOpts  = VerifyConfig{acceptedStateTransitionDelay: time.Minute * 5}
	defaultProofVerifyOpts = VerifyConfig{acceptedStateTransitionDelay: time.Hour,
		acceptedProofGenerationDelay: time.Hour * 24}
)

// WithAcceptedStateTransitionDelay sets the delay of the revoked state.
func WithAcceptedStateTransitionDelay(duration time.Duration) VerifyOpt {
	return func(v *VerifyConfig) {
		v.acceptedStateTransitionDelay = duration
	}
}

// WithAcceptedProofGenerationDelay sets the delay of the proof generation.
func WithAcceptedProofGenerationDelay(duration time.Duration) VerifyOpt {
	return func(v *VerifyConfig) {
		v.acceptedProofGenerationDelay = duration
	}
}

// VerifyOpt sets options.
type VerifyOpt func(v *VerifyConfig)

// VerifyConfig verifiers options.
type VerifyConfig struct {
	// is the period of time that a revoked state remains valid.
	acceptedStateTransitionDelay time.Duration
	acceptedProofGenerationDelay time.Duration
}
