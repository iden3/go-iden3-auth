package auth

import (
	"fmt"
	"github.com/iden3/go-auth/communication/protocol"
	"github.com/iden3/go-auth/proofs/signature"
	"github.com/iden3/go-auth/proofs/zeroknowledge"
	types2 "github.com/iden3/go-auth/types"
)

const (
	// Name represents name of the service
	Name = "authorization-service"
	// AuthorizationRequestMessageType defines auth request type of the communication protocol
	AuthorizationRequestMessageType types2.ProtocolMessage = protocol.ProtocolName + "/authorization-request/v1"
	// AuthorizationResponseMessageType defines auth response type of the communication protocol
	AuthorizationResponseMessageType types2.ProtocolMessage = protocol.ProtocolName + "/authorization-response/v1"
)

// CreateAuthorizationRequest creates new authorization request message
func CreateAuthorizationRequest(aud, callbackURL string) *types2.AuthorizationMessageRequest {
	var message types2.AuthorizationMessageRequest

	message.Type = AuthorizationRequestMessageType
	message.Data = types2.AuthorizationMessageRequestData{
		CallbackURL: callbackURL,
		Audience:    aud,
		Scope:       []types2.TypedScope{},
	}
	return &message
}

// Verify performs a verification of authorization response message
func Verify(message types2.Message) (err error) {
	if message.GetType() != AuthorizationResponseMessageType {
		return fmt.Errorf("%s doesn't support %s message type", Name, (message).GetType())
	}
	authorizationContent := message.GetData().(types2.AuthorizationMessageResponseData)

	for _, s := range authorizationContent.Scope {
		switch proof := s.(type) {
		case types2.ZeroKnowledgeProof:
			err = zeroknowledge.VerifyProof(&proof)
			if err != nil {
				return fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
		case types2.SignatureProof:
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
func ExtractMetadata(message types2.Message) (token *UserToken, err error) {
	if message.GetType() != AuthorizationResponseMessageType {
		return nil, fmt.Errorf("%s doesn't support %s message type", Name, message.GetType())
	}
	authorizationContent := message.GetData().(types2.AuthorizationMessageResponseData)

	token = &UserToken{}
	token.Scope = map[string]map[string]interface{}{}
	for _, s := range authorizationContent.Scope {
		switch proof := s.(type) {
		case types2.ZeroKnowledgeProof:
			err = zeroknowledge.ExtractMetadata(&proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.update(string(proof.CircuitID), proof.ProofMetadata)

			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}

		case types2.SignatureProof:
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
