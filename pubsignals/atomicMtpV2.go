package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

// AtomicQueryMTPV2 is a wrapper for circuits.AtomicQueryMTPV2PubSignals.
type AtomicQueryMTPV2 struct {
	circuits.AtomicQueryMTPV2PubSignals
}

// VerifyQuery checks whether the proof matches the query.
func (c *AtomicQueryMTPV2) VerifyQuery(
	ctx context.Context,
	query Query,
	schemaLoader ld.DocumentLoader,
	verifiablePresentation json.RawMessage,
	_ map[string]interface{},
	opts ...VerifyOpt,
) error {
	return query.Check(ctx, schemaLoader, &CircuitOutputs{
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
	}, verifiablePresentation, false, opts...)
}

// VerifyStates verifies user state and issuer claim issuance state in the smart contract.
func (c *AtomicQueryMTPV2) VerifyStates(ctx context.Context,
	stateResolvers map[string]StateResolver, opts ...VerifyOpt) error {

	blockchain, err := core.BlockchainFromID(*c.IssuerID)
	if err != nil {
		return err
	}
	networkID, err := core.NetworkIDFromID(*c.IssuerID)
	if err != nil {
		return err
	}
	resolver, ok := stateResolvers[fmt.Sprintf("%s:%s", blockchain, networkID)]
	if !ok {
		return errors.Errorf("%s resolver not found", resolver)
	}

	issuerStateResolved, err := resolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerClaimIdenState.BigInt())
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
	issuerNonRevStateResolved, err := resolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerClaimNonRevState.BigInt())
	if err != nil {
		return err
	}

	cfg := defaultProofVerifyOpts
	for _, o := range opts {
		o(&cfg)
	}

	if !issuerNonRevStateResolved.Latest && time.Since(
		time.Unix(issuerNonRevStateResolved.TransitionTimestamp, 0),
	) > cfg.AcceptedStateTransitionDelay {
		return ErrIssuerNonRevocationClaimStateIsNotValid
	}

	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *AtomicQueryMTPV2) VerifyIDOwnership(sender string, requestID *big.Int) error {
	if c.RequestID.Cmp(requestID) != 0 {
		return errors.New("invalid requestID in proof")
	}

	did, err := w3c.ParseDID(sender)
	if err != nil {
		return errors.Wrap(err, "sender must be a valid did")
	}
	senderID, err := core.IDFromDID(*did)
	if err != nil {
		return err
	}

	if senderID.String() != c.UserID.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", senderID.String(), c.UserID.String())
	}
	return nil
}
