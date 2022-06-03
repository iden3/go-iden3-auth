package pubsignals

import (
	"context"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/pkg/errors"
	"math/big"
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

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit
func (c *Auth) VerifyIDOwnership(sender string, challenge *big.Int) error {
	if sender != c.UserID.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", sender, c.UserID.String())
	}
	if challenge.Cmp(c.Challenge) != 0 {
		return errors.Errorf("challenge is not used for proof creation, expected , expected %s, challenge from public signals: %s}", challenge.String(), c.Challenge.String())
	}
	return nil
}
