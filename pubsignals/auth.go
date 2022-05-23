package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/pkg/errors"
)

// Auth is a wrapper for circuits.AuthPubSignals
type Auth struct {
	circuits.AuthPubSignals
}

// VerifyQuery is not implemented for auth circuit
func (c *Auth) VerifyQuery(_ context.Context, _ Query, _ loaders.SchemaLoader) error {
	return errors.New("auth circuit doesn't support queries")
}

// VerifyStates verify auth tests
func (c *Auth) VerifyStates(ctx context.Context, stateResolver StateResolver) error {

	resolvedState, err := stateResolver.Resolve(ctx, c.UserID.BigInt(), c.UserState.BigInt())
	if err != nil {
		return err
	}
	// only latest for users are supported
	if !resolvedState.Latest {
		return ErrUserStateIsNotValid
	}
	return nil
}
