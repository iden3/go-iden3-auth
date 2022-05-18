package pubsignals

import (
	"context"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/pkg/errors"
)

// Auth is a wrapper for circuits.AuthPubSignals
type Auth struct {
	circuits.AuthPubSignals
}

// VerifyQuery is not implemented for auth circuit
func (c *Auth) VerifyQuery(ctx context.Context, query Query) error {
	return errors.New("auth circuit doesn't support queries")
}

// VerifyStates verify auth tests
func (c *Auth) VerifyStates(ctx context.Context, opts state.VerificationOptions) error {

	client, err := ethclient.Dial(opts.RPCUrl)
	if err != nil {
		return err
	}
	defer client.Close()
	resolvedState, err := state.Resolve(ctx, client, opts.Contract, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}
	// only latest for users are supported
	if !resolvedState.Latest {
		return ErrUserStateIsNotValid
	}
	return nil
}
