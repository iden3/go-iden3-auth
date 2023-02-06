package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
)

// AtomicSybilMTP is a wrapper for circuits.AtomicSybilMTP.
type AtomicSybilMTP struct {
	circuits.SybilAtomicMTPPubSignals
}

// VerifyQuery verifies query for atomic query mtp circuit.
func (c *AtomicSybilMTP) VerifyQuery(
	ctx context.Context,
	query Query,
	schemaLoader loaders.SchemaLoader,
	disclosureValue json.RawMessage,
) error {
	err := query.CheckRequest(ctx, schemaLoader, &CircuitOutputs{
		IssuerID:       c.IssuerID,
		ClaimSchema:    c.ClaimSchema,
		Timestamp:      c.Timestamp,
		ValueArraySize: c.ValueArraySize,
		CRS:            c.CRS,
	}, disclosureValue)
	if err != nil {
		return err
	}
	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *AtomicSybilMTP) VerifyStates(ctx context.Context, stateResolvers map[string]StateResolver, opts ...VerifyOpt) error {
	userDID, err := core.ParseDIDFromID(*c.UserID)
	if err != nil {
		return err
	}
	chainInfo := fmt.Sprintf("%s:%s", userDID.Blockchain, userDID.NetworkID)
	resolver, ok := stateResolvers[chainInfo]
	if !ok {
		return errors.Errorf("%s resolver not found", chainInfo)
	}

	resolvedState, err := resolver.ResolveGlobalRoot(ctx, c.GISTRoot.BigInt())
	if err != nil {
		return err
	}

	authCfg := defaultAuthVerifyOpts
	for _, o := range opts {
		o(&authCfg)
	}

	if !resolvedState.Latest && time.Since(time.Unix(resolvedState.TransitionTimestamp, 0)) > authCfg.acceptedStateTransitionDelay {
		return ErrGlobalStateIsNotValid
	}

	issuerStateResolved, err := resolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerClaimIdenState.BigInt())
	if err != nil {
		return err
	}

	if issuerStateResolved == nil {
		return ErrIssuerClaimStateIsNotValid
	}

	issuerNonRevStateResolved, err := resolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerClaimNonRevState.BigInt())
	if err != nil {
		return err
	}

	proofCfg := defaultProofVerifyOpts
	for _, o := range opts {
		o(&proofCfg)
	}

	if !issuerNonRevStateResolved.Latest && time.Since(
		time.Unix(issuerNonRevStateResolved.TransitionTimestamp, 0),
	) > proofCfg.acceptedStateTransitionDelay {
		return ErrIssuerNonRevocationClaimStateIsNotValid
	}

	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *AtomicSybilMTP) VerifyIDOwnership(sender string, requestID *big.Int) error {
	if c.RequestID.Cmp(requestID) != 0 {
		return errors.New("invalid requestID in proof")
	}

	userDID, err := core.ParseDIDFromID(*c.UserID)
	if err != nil {
		return err
	}
	if sender != userDID.String() {
		return fmt.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", sender, c.UserID.String())
	}
	return nil
}
