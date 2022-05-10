package pubsignals

import (
	"github.com/iden3/go-iden3-auth/state"
	"time"
)

// VerificationOptions is options for state verification
type VerificationOptions struct {
	Contract           string
	BlockchainProvider state.BlockchainCaller

	OnlyLatestStates             bool
	AcceptedStateTransitionDelay time.Duration
}
