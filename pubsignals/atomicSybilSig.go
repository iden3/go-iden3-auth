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

// AtomicSybilSig is a wrapper for circuits.AtomicSybilSig.
type AtomicSybilSig struct {
	circuits.SybilAtomicSigPubSignals
}

// VerifyQuery verifies query for atomic query sig circuit.
func (c *AtomicSybilSig) VerifyQuery(
	ctx context.Context,
	query Query,
	schemaLoader loaders.SchemaLoader,
	disclosureValue json.RawMessage,
) error {

	if err := query.verifyIssuer(c.IssuerID); err != nil {
		return err
	}

	if err := query.verifySchemaID(c.ClaimSchema); err != nil {
		return err
	}

	if err := query.verifyCRS(c.CRS); err != nil {
		return err
	}

	if err := query.verifyGISTRoot(c.GISTRoot); err != nil {
		return err
	}

	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *AtomicSybilSig) VerifyStates(ctx context.Context, stateResolvers map[string]StateResolver, opts ...VerifyOpt) error {
	issuerDID, err := core.ParseDIDFromID(*c.IssuerID)
	if err != nil {
		return err
	}
	resolver, ok := stateResolvers[fmt.Sprintf("%s:%s", issuerDID.Blockchain, issuerDID.NetworkID)]
	if !ok {
		return errors.Errorf("%s resolver not found", resolver)
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
func (c *AtomicSybilSig) VerifyIDOwnership(sender string, requestID *big.Int) error {
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
