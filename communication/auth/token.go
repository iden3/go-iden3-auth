package auth

import (
	"errors"
	"github.com/iden3/go-auth/types"
)

// UserToken is token that can be used for user authorization
type UserToken struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
	Scope     map[string]map[string]interface{}
}

func (token *UserToken) update(scopeID string, metadata types.ProofMetadata) error {

	if token.Challenge != "" && token.Challenge != metadata.AuthData.AuthenticationChallenge {
		return errors.New("different challenges were used for authentication")
	}
	if token.ID != "" && token.ID != metadata.AuthData.UserIdentifier {
		return errors.New("different identifiers were used for authentication")
	}
	token.Challenge = metadata.AuthData.AuthenticationChallenge
	token.ID = metadata.AuthData.UserIdentifier

	if metadata.AdditionalData != nil {
		token.Scope[scopeID] = metadata.AdditionalData
	}

	return nil
}
