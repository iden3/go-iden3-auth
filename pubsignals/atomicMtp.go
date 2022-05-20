package pubsignals

import (
	"context"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/state"
)

// AtomicQueryMTP is a wrapper for circuits.AtomicQueryMTPPubSignals
type AtomicQueryMTP struct {
	circuits.AtomicQueryMTPPubSignals
}

// VerifyQuery verifies query for atomic query mtp circuit
func (c *AtomicQueryMTP) VerifyQuery(ctx context.Context, query Query) error {

	err := query.CheckRequest(ctx, c.IssuerID, c.ClaimSchema, c.SlotIndex, c.Values, c.Operator)
	if err != nil {
		return err
	}
	return nil
}

// VerifyStates verifies user state and issuer claim issuance state in the smart contract
func (c *AtomicQueryMTP) VerifyStates(ctx context.Context, opts state.VerificationOptions) error {

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
	issuerStateResolved, err := state.Resolve(ctx, client, opts.Contract, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}
	if issuerStateResolved == nil {
		return ErrUserStateIsNotValid
	}

	return nil
}
