package pubsignals

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
)

type AtomicQueryMTPV2 struct {
	circuits.AtomicQueryMTPV2PubSignals
}

func (c *AtomicQueryMTPV2) VerifyQuery(ctx context.Context, query Query, schemaLoader loaders.SchemaLoader) error {
	return query.CheckRequest(ctx, schemaLoader, &AtomicPubSignals{
		IssuerID:           c.IssuerID,
		ClaimSchema:        c.ClaimSchema,
		SlotIndex:          c.SlotIndex,
		Operator:           c.Operator,
		Value:              c.Value,
		Timestamp:          c.Timestamp,
		Merklized:          c.Merklized,
		ClaimPathKey:       c.ClaimPathKey,
		ClaimPathNotExists: c.ClaimPathNotExists,
		ValueArraySize:     c.ValueArraySize,
	})
}

// For sig check issuer auth claim

// VerifyStates verifies user state and issuer claim issuance state in the smart contract
func (c *AtomicQueryMTPV2) VerifyStates(ctx context.Context, stateResolver StateResolver) error {
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
func (c *AtomicQueryMTPV2) VerifyIDOwnership(sender string, requestID *big.Int) error {
	if c.RequestID.Cmp(requestID) != 0 {
		return errors.New("invalid requestID in proof")
	}

	if sender != c.UserID.String() {
		return fmt.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", sender, c.UserID.String())
	}
	return nil
}
