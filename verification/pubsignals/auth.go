package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/verification"
	"github.com/pkg/errors"
	"time"
)

type Auth struct {
	circuits.AuthPubSignals
}

func (c *Auth) VerifyQuery(ctx context.Context, query Query) error {

	return errors.New("auth circuit doesn't support queries")
}

func (c *Auth) VerifyStates(ctx context.Context, opts VerificationOptions) error {

	userStateVerification, err := verification.VerifyState(ctx, opts.BlockchainProvider, opts.Contract, c.UserID.BigInt(), c.UserState.BigInt())
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
