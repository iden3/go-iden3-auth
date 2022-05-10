package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/pkg/errors"
	"time"
)

// Auth is a wrapper for circuits.AuthPubSignals
type Auth struct {
	circuits.AuthPubSignals
}

// VerifyQuery is not implemented for auth circuit
func (c *Auth) VerifyQuery(ctx context.Context, query Query) error {

	return errors.New("auth circuit doesn't support queries")
}

// VerifyStates verify auth tests
func (c *Auth) VerifyStates(ctx context.Context, opts VerificationOptions) error {

	userStateVerification, err := state.Verify(ctx, opts.BlockchainProvider, opts.Contract, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}

	if !userStateVerification.Latest {
		if opts.OnlyLatestStates {
			return errors.New("user state is not latest")
		}
		transitionTime := time.Unix(userStateVerification.TransitionTimestamp, 0)
		if time.Now().Sub(transitionTime) > opts.AcceptedStateTransitionDelay {
			return errors.New("user state is not latest and lost actuality")
		}
	}
	return nil
}
