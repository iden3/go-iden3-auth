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

// AtomicQuerySigV2 is a wrapper for circuits.AtomicQuerySigV2PubSignals.
type AtomicQuerySigV2 struct {
	circuits.AtomicQuerySigV2PubSignals
}

// VerifyQuery verifies query for atomic query mtp circuit.
func (c *AtomicQuerySigV2) VerifyQuery(ctx context.Context, query Query, schemaLoader loaders.SchemaLoader) error {
	err := query.CheckRequest(ctx, schemaLoader, &AtomicPubSignals{
		IssuerID:            c.IssuerID,
		ClaimSchema:         c.ClaimSchema,
		SlotIndex:           c.SlotIndex,
		Operator:            c.Operator,
		Value:               c.Value,
		Timestamp:           c.Timestamp,
		Merklized:           c.Merklized,
		ClaimPathKey:        c.ClaimPathKey,
		ClaimPathNotExists:  c.ClaimPathNotExists,
		ValueArraySize:      c.ValueArraySize,
		IsRevocationChecked: c.IsRevocationChecked,
	})
	if err != nil {
		return err
	}
	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *AtomicQuerySigV2) VerifyStates(ctx context.Context, stateResolver StateResolver) error {
	issuerStateResolved, err := stateResolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerAuthState.BigInt())
	if err != nil {
		return err
	}
	if issuerStateResolved == nil {
		return ErrIssuerClaimStateIsNotValid
	}

	// if IsRevocationChecked is set to 0. Skip validation revocation status of issuer.
	if c.IsRevocationChecked == 0 {
		return nil
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

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *AtomicQuerySigV2) VerifyIDOwnership(sender string, requestID *big.Int) error {
	if c.RequestID.Cmp(requestID) != 0 {
		return errors.New("invalid requestID in proof")
	}

	userDID, err := core.ParseDIDFromID(*c.UserID)
	if err != nil {
		return err
	}
	if sender != userDID.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", sender, c.UserID.String())
	}
	return nil
}
