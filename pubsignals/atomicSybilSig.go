package pubsignals

import (
	"context"
	"fmt"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
	"math/big"
	"time"
)

type AtomicSybilSig struct {
	circuits.SybilAtomicSigPubSignals
}

func (c *AtomicSybilSig) VerifyQuery(
	_ context.Context,
	_ Query,
	_ loaders.SchemaLoader,
	_ interface{}) error {
	return errors.New("atomicSybilSig circuit doesn't support queries")
}

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

	cfg := defaultAuthVerifyOpts
	for _, o := range opts {
		o(&cfg)
	}

	if !resolvedState.Latest && time.Since(time.Unix(resolvedState.TransitionTimestamp, 0)) > cfg.acceptedStateTransitionDelay {
		return ErrGlobalStateIsNotValid
	}
	return nil
}

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
