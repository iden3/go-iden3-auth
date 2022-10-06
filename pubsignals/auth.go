package pubsignals

import (
	"context"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
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

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit
func (c *Auth) VerifyIDOwnership(sender string, challenge *big.Int) error {

	//  parse did from core id
	did, err := core.ParseDIDFromID(*c.UserID)
	if err != nil {
		return errors.Errorf("user identifer is not a valid DID, expected %s, identifier from public signals: %s}", sender, c.UserID.String())
	}
	if sender != did.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user did from public signals: %s}", sender, did.String())
	}
	if challenge.Cmp(c.Challenge) != 0 {
		return errors.Errorf("challenge is not used for proof creation, expected , expected %s, challenge from public signals: %s}", challenge.String(), c.Challenge.String())
	}
	return nil
}
