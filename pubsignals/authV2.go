package pubsignals

import (
	"context"
	core "github.com/iden3/go-iden3-core"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/pkg/errors"
)

// AuthV2 is a wrapper for circuits.AuthV2PubSignals
type AuthV2 struct {
	circuits.AuthV2PubSignals
}

// VerifyQuery is not implemented for authV2 circuit
func (c *AuthV2) VerifyQuery(_ context.Context, _ Query, _ loaders.SchemaLoader) error {
	return errors.New("authV2 circuit doesn't support queries")
}

// VerifyStates verify AuthV2 tests
func (c *AuthV2) VerifyStates(ctx context.Context, stateResolver StateResolver) error {

	resolvedState, err := stateResolver.ResolveGlobalRoot(ctx, c.GlobalRoot.BigInt())
	if err != nil {
		return err
	}
	// only latest for users are supported
	if !resolvedState.Latest {
		return ErrGlobalStateIsNotValid
	}
	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit
func (c *AuthV2) VerifyIDOwnership(sender string, challenge *big.Int) error {
	userDID, err := core.ParseDIDFromID(*c.UserID)
	if err != nil {
		return err
	}

	if sender != userDID.String() {
		return errors.Errorf("sender is not used for proof creation, expected %s, user from public signals: %s}", sender, userDID)
	}
	if challenge.Cmp(c.Challenge) != 0 {
		return errors.Errorf("challenge is not used for proof creation, expected , expected %s, challenge from public signals: %s}", challenge.String(), c.Challenge.String())
	}
	return nil
}
