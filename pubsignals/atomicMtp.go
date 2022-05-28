package pubsignals

import (
	"context"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
)

// AtomicQueryMTP is a wrapper for circuits.AtomicQueryMTPPubSignals
type AtomicQueryMTP struct {
	circuits.AtomicQueryMTPPubSignals
}

// VerifyQuery verifies query for atomic query mtp circuit
func (c *AtomicQueryMTP) VerifyQuery(ctx context.Context, query Query, schemaLoader loaders.SchemaLoader) error {

	return query.CheckRequest(ctx, schemaLoader, ClaimOutputs{
		IssuerID:   c.IssuerID,
		SchemaHash: c.ClaimSchema,
		SlotIndex:  c.SlotIndex,
		Operator:   c.Operator,
		Value:      c.Values,
	})
}

// VerifyStates verifies user state and issuer claim issuance state in the smart contract
func (c *AtomicQueryMTP) VerifyStates(ctx context.Context, stateResolver StateResolver) error {

	userStateResolved, err := stateResolver.Resolve(ctx, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}
	if !userStateResolved.Latest {
		return ErrUserStateIsNotValid
	}
	issuerStateResolved, err := stateResolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerClaimIdenState.BigInt())
	if err != nil {
		return err
	}
	if issuerStateResolved == nil {
		return ErrIssuerClaimStateIsNotValid
	}

	return nil
}
