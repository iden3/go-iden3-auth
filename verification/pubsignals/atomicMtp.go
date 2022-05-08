package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/verification"
	"github.com/pkg/errors"
	"time"
)

type AtomicQueryMTP struct {
	circuits.AtomicQueryMTPPubSignals
}

func (c *AtomicQueryMTP) VerifyQuery(ctx context.Context, query Query) error {

	if !query.CheckIssuer(c.IssuerID.String()) {
		return errors.New("issuer of claim is not in allowed list")
	}
	err := query.CheckSchema(c.ClaimSchema)
	if err != nil {
		return err
	}

	// TODO: add more checks

	return nil
}

func (c *AtomicQueryMTP) VerifyStates(ctx context.Context, opts VerificationOptions) error {

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

	issuerStateVerification, err := verification.VerifyState(ctx, opts.BlockchainProvider, opts.Contract, c.IssuerID.BigInt(), c.IssuerClaimIdenState.BigInt())
	if err != nil {
		return err
	}
	if !issuerStateVerification.Latest {
		if opts.OnlyLatestStates {
			return errors.New("issuer state is not latest")
		}
		transitionTime := time.Unix(issuerStateVerification.TransitionTimestamp, 0)
		if time.Now().Sub(transitionTime) > opts.AcceptedStateTransitionDelay {
			return errors.New("issuer state is not latest and lost actuality")
		}
	}

	return nil
}
