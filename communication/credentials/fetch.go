package credentials

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-iden3-auth/communication/auth"
	"github.com/iden3/go-iden3-auth/communication/protocol"
	"github.com/iden3/go-iden3-auth/proofs/signature"
	"github.com/iden3/go-iden3-auth/proofs/zeroknowledge"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/pkg/errors"
)

const (
	// Name represents name of the service
	Name = "credential-service"
	// CredentialFetchRequestMessageType defines credential request type of the communication protocol
	CredentialFetchRequestMessageType types.ProtocolMessage = protocol.ProtocolName + "/credential-fetch-request/v1"
)

// VerifyCredentialFetchRequest only proofs of  a verification of credential fetch request  message
func VerifyCredentialFetchRequest(message types.Message) (err error) {
	if message.GetType() != CredentialFetchRequestMessageType {
		return fmt.Errorf("%s doesn't support %s message type", Name, (message).GetType())
	}

	var fetchRequestData types.CredentialFetchRequestMessageData

	switch message.GetData().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetData().(json.RawMessage), &fetchRequestData)
		if err != nil {
			return err
		}
	case types.CredentialFetchRequestMessageData:
		fetchRequestData = message.GetData().(types.CredentialFetchRequestMessageData)
	}

	if fetchRequestData.ClaimID == "" {
		return errors.New("no claim field in fetch request")
	}

	if fetchRequestData.Schema == "" {
		return errors.New("no claim schema field in fetch request")
	}

	for _, s := range fetchRequestData.Scope {
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
			return errors.New("unknown proof")
		}
	}
	return nil
}

// ExtractMetadataFromCredentialFetchRequest extract CredentialFetch specific fetchCredToken from provided proofs
func ExtractMetadataFromCredentialFetchRequest(message types.Message) (fetchCredToken *CredentialFetchUserToken, err error) {
	if message.GetType() != CredentialFetchRequestMessageType {
		return nil, fmt.Errorf("%s doesn't support %s message type", Name, message.GetType())
	}
	var fetchRequestData types.CredentialFetchRequestMessageData

	switch message.GetData().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetData().(json.RawMessage), &fetchRequestData)
		if err != nil {
			return nil, err
		}
	case types.CredentialFetchRequestMessageData:
		fetchRequestData = message.GetData().(types.CredentialFetchRequestMessageData)
	}
	fetchCredToken = &CredentialFetchUserToken{
		ClaimID:     fetchRequestData.ClaimID,
		ClaimSchema: fetchRequestData.Schema,
	}
	fetchCredToken.Scope = map[string]map[string]interface{}{}
	for _, s := range fetchRequestData.Scope {

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
			err = fetchCredToken.Update(string(proof.CircuitID), proof.ProofMetadata)

			if err != nil {
				return nil, fmt.Errorf("can't provide user fetchCredToken %s", err.Error())
			}

		case types.SignatureProof:
			err = signature.ExtractMetadata(&proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = fetchCredToken.Update(proof.KeyType, proof.ProofMetadata)
			if err != nil {
				return nil, fmt.Errorf("can't provide user fetchCredToken %s", err.Error())
			}
		}
	}
	return fetchCredToken, nil
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

// CredentialFetchUserToken is token to fetch credential
type CredentialFetchUserToken struct {
	ClaimID     string `json:"claim_id"`
	ClaimSchema string `json:"claim_schema"`
	auth.UserToken
}
