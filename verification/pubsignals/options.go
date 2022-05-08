package pubsignals

import (
	"github.com/iden3/go-iden3-auth/verification"
	"time"
)

type VerificationOptions struct {
	Contract           string
	BlockchainProvider verification.BlockchainCaller

	OnlyLatestStates             bool
	AcceptedStateTransitionDelay time.Duration
}
