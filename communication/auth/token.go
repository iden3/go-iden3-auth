package auth

import (
	"context"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/iden3/go-iden3-auth/verification"
	"github.com/pkg/errors"

	core "github.com/iden3/go-iden3-core"
	"math/big"
)

// UserToken is token that can be used for user authorization
type UserToken struct {
	ID        string                            `json:"id"`
	Challenge string                            `json:"challenge"`
	State     string                            `json:"state"`
	Scope     map[string]map[string]interface{} `json:"scope"`
}

// Update adds new metadata to user token
func (token *UserToken) Update(scopeID string, metadata types.ProofMetadata) error {

	if token.Challenge != "" && token.Challenge != metadata.AuthData.AuthenticationChallenge {
		return errors.New("different challenges were used for authentication")
	}
	if token.ID != "" && token.ID != metadata.AuthData.UserIdentifier {
		return errors.New("different identifiers were used for authentication")
	}

	// TODO: make a decision if each proof must contain user state
	if token.State == "" && metadata.AuthData.UserState != "" {
		token.State = metadata.AuthData.UserState
	}

	token.Challenge = metadata.AuthData.AuthenticationChallenge
	token.ID = metadata.AuthData.UserIdentifier

	if metadata.AdditionalData != nil {
		token.Scope[scopeID] = metadata.AdditionalData
	}

	return nil
}

// VerifyState verifies state that is stored in the token
func (token *UserToken) VerifyState(ctx context.Context, url, addr string) (verification.StateVerificationResult, error) {
	id, err := core.IDFromString(token.ID)
	if err != nil {
		return verification.StateVerificationResult{}, nil
	}
	//  prepare msg data

	stateBigInt, ok := new(big.Int).SetString(token.State, 10)
	if !ok {
		return verification.StateVerificationResult{}, errors.Errorf("can't create big int from string %s", token.State)
	}
	return verification.VerifyState(context.Background(), url, addr, id.BigInt(), stateBigInt)

}
