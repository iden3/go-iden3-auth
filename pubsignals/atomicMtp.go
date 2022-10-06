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
func (c *AtomicQueryMTP) VerifyIDOwnership(sender string, challenge *big.Int) error {
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
