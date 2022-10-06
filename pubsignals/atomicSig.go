package pubsignals

import (
	"context"
	"math/big"
	"time"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
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

	issuerNonRevStateResolved, err := stateResolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerClaimNonRevState.BigInt())
	if err != nil {
		return err
	}
	if !issuerNonRevStateResolved.Latest && time.Since(time.Unix(issuerNonRevStateResolved.TransitionTimestamp, 0)) > time.Hour {
		return ErrIssuerNonRevocationClaimStateIsNotValid
	}

	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit
func (c *AtomicQuerySig) VerifyIDOwnership(sender string, challenge *big.Int) error {
	//  parse did from core id
	did, err := core.ParseDIDFromID(*c.UserID)
	if err != nil {
		return errors.Errorf("user identifer is not a valid DID, expected %s, identifier from public signals: %s}", sender, c.UserID.String())
	}
	if sender != did.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user did from public signals: %s}", sender, did.String())
	}
	if challenge.Cmp(c.Challenge) != 0 {
		return errors.Errorf("challenge is not used for proof creation, expected , expected %s, challenge from public signals: %s}", challenge.String(), c.Challenge.String())
	}
	return nil
}
