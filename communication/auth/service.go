package auth

import (
	"encoding/json"
	"fmt"

	"github.com/iden3/go-iden3-auth/communication/protocol"
	"github.com/iden3/go-iden3-auth/proofs/signature"
	"github.com/iden3/go-iden3-auth/proofs/zeroknowledge"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/pkg/errors"
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
func CreateAuthorizationRequest(challenge int64, aud, callbackURL string) *types.AuthorizationMessageRequest {
	var message types.AuthorizationMessageRequest

	message.Type = AuthorizationRequestMessageType
	message.Data = types.AuthorizationMessageRequestData{
		CallbackURL: callbackURL,
		Audience:    aud,
		Scope:       []types.TypedScope{},
	}

	message.WithDefaultZKAuth(challenge)

	return &message
}

// VerifyProofs verifies only zk proofs of authorization response message
func VerifyProofs(message types.Message) (err error) {
	if message.GetType() != AuthorizationResponseMessageType {
		return fmt.Errorf("%s doesn't support %s message type", Name, (message).GetType())
	}

	var authorizationResponseData types.AuthorizationMessageResponseData

	switch message.GetData().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetData().(json.RawMessage), &authorizationResponseData)
		if err != nil {
			return err
		}
	case types.AuthorizationMessageResponseData:
		authorizationResponseData = message.GetData().(types.AuthorizationMessageResponseData)
	}

	for _, s := range authorizationResponseData.Scope {
		var typedScope types.TypedScope
		typedScope, err = toTypedScope(s)
		if err != nil {
			return err
		}
		switch proof := typedScope.(type) {
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
		default:
			fmt.Println(proof)
			return errors.New("unknown proof")
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
	var authorizationResponseData types.AuthorizationMessageResponseData

	switch message.GetData().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetData().(json.RawMessage), &authorizationResponseData)
		if err != nil {
			return nil, err
		}
	case types.AuthorizationMessageResponseData:
		authorizationResponseData = message.GetData().(types.AuthorizationMessageResponseData)
	}
	token = &UserToken{}
	token.Scope = map[string]map[string]interface{}{}
	for _, s := range authorizationResponseData.Scope {

		var typedScope types.TypedScope
		typedScope, err = toTypedScope(s)
		if err != nil {
			return nil, err
		}
		switch proof := typedScope.(type) {
		case types.ZeroKnowledgeProof:
			err = zeroknowledge.ExtractMetadata(&proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.Update(string(proof.CircuitID), proof.ProofMetadata)

			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}

		case types.SignatureProof:
			err = signature.ExtractMetadata(&proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.Update(proof.KeyType, proof.ProofMetadata)
			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}
		}
	}
	return token, nil
}

func toTypedScope(value interface{}) (types.TypedScope, error) {
	switch obj := value.(type) {
	case map[string]interface{}:
		scopeMap, ok := value.(map[string]interface{})
		if !ok {
			return nil, errors.New("scope object is not a map")
		}
		b, err := json.Marshal(value)
		if err != nil {
			return nil, errors.Wrap(err, "can't marshall scope obj")
		}
		switch types.ProofType(scopeMap["type"].(string)) {
		case types.ZeroKnowledgeProofType:
			var zkp types.ZeroKnowledgeProof
			err = json.Unmarshal(b, &zkp)
			if err != nil {
				return nil, errors.Wrap(err, "can't unmarshall to zkp proof")
			}
			return zkp, nil
		case types.SignatureProofType:
			var sig types.SignatureProof
			err = json.Unmarshal(b, &sig)
			if err != nil {
				return nil, errors.Wrap(err, "can't unmarshall to signature proof")
			}
			return sig, nil
		default:
			return nil, errors.Errorf("proof type is not supported: %s ", scopeMap["type"])
		}
	case types.TypedScope:
		return obj, nil
	default:
		return nil, errors.Errorf("scope object type is not supported %v", value)
	}
}
