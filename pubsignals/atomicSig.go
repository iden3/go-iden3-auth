package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/pkg/errors"
	"math/big"
)

// AtomicQuerySig is a wrapper for circuits.AtomicQuerySigPubSignals
type AtomicQuerySig struct {
	circuits.AtomicQuerySigPubSignals
}

// VerifyQuery verifies query for atomic query mtp circuit
func (c *AtomicQuerySig) VerifyQuery(ctx context.Context, query Query, schemaLoader loaders.SchemaLoader) error {

	err := query.CheckRequest(ctx, schemaLoader, ClaimOutputs{
		IssuerID:   c.IssuerID,
		SchemaHash: c.ClaimSchema,
		SlotIndex:  c.SlotIndex,
		Operator:   c.Operator,
		Value:      c.Values,
	})

	if err != nil {
		return err
	}
	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract
func (c *AtomicQuerySig) VerifyStates(ctx context.Context, stateResolver StateResolver) error {

	userStateResolved, err := stateResolver.Resolve(ctx, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}

	if !userStateResolved.Latest {
		return ErrUserStateIsNotValid
	}
	issuerStateResolved, err := stateResolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerAuthState.BigInt())
	if err != nil {
		return err
	}
	if issuerStateResolved == nil {
		return ErrIssuerClaimStateIsNotValid
	}

	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit
func (c *AtomicQuerySig) VerifyIDOwnership(sender string, challenge *big.Int) error {
	if sender != c.UserID.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", sender, c.UserID.String())
	}
	if challenge.Cmp(c.Challenge) != 0 {
		return errors.Errorf("challenge is not used for proof creation, expected , expected %s, challenge from public signals: %s}", challenge.String(), c.Challenge.String())
	}
	return nil
}
