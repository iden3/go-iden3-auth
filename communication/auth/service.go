package auth

import (
	"fmt"
	"github.com/iden3/go-iden3-auth/communication/protocol"
	"github.com/iden3/go-iden3-auth/proofs/signature"
	"github.com/iden3/go-iden3-auth/proofs/zeroknowledge"
	"github.com/iden3/go-iden3-auth/types"
)

const (
	// Name represents name of the service
	Name = "authorization-service"
	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType types.ProtocolMessage = protocol.ProtocolName + "/authorization-request/v1"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType types.ProtocolMessage = protocol.ProtocolName + "/authorization-response/v1"
)

// CreateAuthorizationRequest creates new authorization request message
func CreateAuthorizationRequest(aud, callbackURL string) *types.AuthorizationMessageRequest {
	var message types.AuthorizationMessageRequest

	message.Type = AuthorizationRequestMessageType
	message.Data = types.AuthorizationMessageRequestData{
		CallbackURL: callbackURL,
		Audience:    aud,
		Scope:       []types.TypedScope{},
	}
	return &message
}

// Verify only proofs of  a verification of authorization response message
//
func Verify(message types.Message) (err error) {
	if message.GetType() != AuthorizationResponseMessageType {
		return fmt.Errorf("%s doesn't support %s message type", Name, (message).GetType())
	}
	authorizationContent := message.GetData().(types.AuthorizationMessageResponseData)

	for _, s := range authorizationContent.Scope {
		switch proof := s.(type) {
		case types.ZeroKnowledgeProof:
			err = zeroknowledge.VerifyProof(&proof)
			if err != nil {
				return fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
		case types.SignatureProof:
			err = signature.VerifyProof(&proof)
			if err != nil {
				return fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
		}
		// TODO: throw error on unknown proof
	}
	return nil
}

// ExtractMetadata extract userToken from provided proofs
func ExtractMetadata(message types.Message) (token *UserToken, err error) {
	if message.GetType() != AuthorizationResponseMessageType {
		return nil, fmt.Errorf("%s doesn't support %s message type", Name, message.GetType())
	}
	authorizationContent := message.GetData().(types.AuthorizationMessageResponseData)

	token = &UserToken{}
	token.Scope = map[string]map[string]interface{}{}
	for _, s := range authorizationContent.Scope {
		switch proof := s.(type) {
		case types.ZeroKnowledgeProof:
			err = zeroknowledge.ExtractMetadata(&proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.update(string(proof.CircuitID), proof.ProofMetadata)

			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}

		case types.SignatureProof:
			err = signature.ExtractMetadata(&proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.update(proof.KeyType, proof.ProofMetadata)
			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}
		}

		// TODO: throw error on unknown proof

	}
	return token, nil
}
