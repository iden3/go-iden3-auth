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
	verifiable "github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

// AtomicQueryV3 is a wrapper for circuits.AtomicQueryV3PubSignals.
type AtomicQueryV3 struct {
	circuits.AtomicQueryV3PubSignals
}

// VerifyQuery verifies query for atomic query V3 circuit.
func (c *AtomicQueryV3) VerifyQuery(
	ctx context.Context,
	query Query,
	schemaLoader ld.DocumentLoader,
	verifiablePresentation json.RawMessage,
	opts ...VerifyOpt,
) error {
	err := query.Check(ctx, schemaLoader, &CircuitOutputs{
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
		// V3 NEW
		LinkID:            c.LinkID,
		VerifierID:        c.VerifierID,
		VerifierSessionID: c.VerifierSessionID,
		OperatorOutput:    c.OperatorOutput,
		Nullifier:         c.Nullifier,
		ProofType:         c.ProofType,
	}, verifiablePresentation, opts...)
	if err != nil {
		return err
	}

	// V3 NEW
	switch query.ProofType {
	case string(verifiable.BJJSignatureProofType):
		if c.ProofType != 1 {
			return ErrWronProofType
		}
	case string(verifiable.Iden3SparseMerkleTreeProofType):
		if c.ProofType != 2 {
			return ErrWronProofType
		}
	default:
	}

	// verify nullifier information
	if c.Nullifier != nil && c.Nullifier.Cmp(big.NewInt(0)) != 0 {
		cfg := defaultProofVerifyOpts
		for _, o := range opts {
			o(&cfg)
		}
		id, err := core.IDFromDID(*cfg.VerifierDID)
		if err != nil {
			return err
		}
		if c.VerifierID.BigInt().Cmp(id.BigInt()) != 0 {
			return errors.New("wrong verifier is used for nullification")
		}

		verifierSessionID, ok := new(big.Int).SetString(query.VerifierSessionID, 10)
		if !ok {
			return errors.Errorf("verifier session id is not valid big int %s", verifierSessionID.String())
		}
		if c.VerifierSessionID != verifierSessionID {
			return errors.Errorf("wrong verifier session id is used for nullification: expected %s given %s,", verifierSessionID.String(), c.VerifierSessionID.String())
		}
	}

	if query.LinkSessionID != "" && c.LinkID == nil {
		return errors.New("proof doesn't contain link id, but link session id is provided")
	}

	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *AtomicQueryV3) VerifyStates(ctx context.Context, stateResolvers map[string]StateResolver, opts ...VerifyOpt) error {
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

	issuerStateResolved, err := resolver.Resolve(ctx, c.IssuerID.BigInt(), c.IssuerState.BigInt())
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
func (c *AtomicQueryV3) VerifyIDOwnership(sender string, requestID *big.Int) error {
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
