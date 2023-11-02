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

// AuthV2 is a wrapper for circuits.AuthV2PubSignals.
type AuthV2 struct {
	circuits.AuthV2PubSignals
}

// VerifyQuery is not implemented for authV2 circuit.
func (c *AuthV2) VerifyQuery(
	_ context.Context,
	_ Query,
	_ ld.DocumentLoader,
	_ json.RawMessage,
	_ ...VerifyOpt) error {
	return errors.New("authV2 circuit doesn't support queries")
}

// VerifyStates verify AuthV2 tests.
func (c *AuthV2) VerifyStates(ctx context.Context, stateResolvers map[string]StateResolver, opts ...VerifyOpt) error {
	blockchain, err := core.BlockchainFromID(*c.UserID)
	if err != nil {
		return err
	}
	networkID, err := core.NetworkIDFromID(*c.UserID)
	if err != nil {
		return err
	}
	chainInfo := fmt.Sprintf("%s:%s", blockchain, networkID)
	resolver, ok := stateResolvers[chainInfo]
	if !ok {
		return errors.Errorf("%s resolver not found", chainInfo)
	}

	resolvedState, err := resolver.ResolveGlobalRoot(ctx, c.GISTRoot.BigInt())
	if err != nil {
		return err
	}

	cfg := defaultAuthVerifyOpts
	for _, o := range opts {
		o(&cfg)
	}

	if !resolvedState.Latest && time.Since(time.Unix(resolvedState.TransitionTimestamp, 0)) > cfg.AcceptedStateTransitionDelay {
		return ErrGlobalStateIsNotValid
	}
	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *AuthV2) VerifyIDOwnership(sender string, challenge *big.Int) error {
	if challenge.Cmp(c.Challenge) != 0 {
		return errors.Errorf("challenge is not used for proof creation, expected , expected %s, challenge from public signals: %s}", challenge.String(), c.Challenge.String())
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

// VerifyVerifierID returns error if verifier ID wasn't match with circuit output.
func (c *AuthV2) VerifyVerifierID(_ string) error {
	return nil
}
