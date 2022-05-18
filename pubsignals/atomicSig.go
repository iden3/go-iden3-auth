package pubsignals

import (
	"context"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/pkg/errors"
)

// AtomicQuerySig is a wrapper for circuits.AtomicQuerySigPubSignals
type AtomicQuerySig struct {
	circuits.AtomicQuerySigPubSignals
}

// VerifyQuery verifies query for atomic query mtp circuit
func (c *AtomicQuerySig) VerifyQuery(ctx context.Context, query Query) error {

	if !query.CheckIssuer(c.IssuerID.String()) {
		return errors.New("issuer of claim is not in allowed list")
	}
	err := query.CheckSchema(ctx, c.ClaimSchema)
	if err != nil {
		return err
	}

	//
	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract
func (c *AtomicQuerySig) VerifyStates(ctx context.Context, opts state.VerificationOptions) error {

	client, err := ethclient.Dial(opts.RPCUrl)
	if err != nil {
		return err
	}
	defer client.Close()
	userStateResolved, err := state.Resolve(ctx, client, opts.Contract, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}

	if !userStateResolved.Latest {
		return ErrUserStateIsNotValid
	}
	issuerStateResolved, err := state.Resolve(ctx, client, opts.Contract, c.IssuerID.BigInt(), c.IssuerAuthState.BigInt())
	if err != nil {
		return err
	}
	if issuerStateResolved == nil {
		return ErrUserStateIsNotValid
	}

	return nil
}
