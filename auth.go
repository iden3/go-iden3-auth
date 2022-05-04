package auth

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/proofs"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/iden3/iden3comm/protocol/auth"
	"github.com/iden3/iden3comm/protocol/credentials"
	"github.com/pkg/errors"
)

// AuthorizationMessageRequestBody is struct the represents authorization request data
type AuthorizationMessageRequestBody struct {
	CallbackURL string                                 `json:"callbackUrl"`
	Audience    string                                 `json:"audience"`
	Scope       []verifiable.ZeroKnowledgeProofRequest `json:"scope"`
}

// AuthorizationMessageRequest is struct the represents authentication request message format
type AuthorizationMessageRequest struct {
	iden3comm.BasicMessage
	Body AuthorizationMessageRequestBody `json:"body"`
}

// WithZeroKnowledgeProofRequest adds zkp proof to scope of request
func (m *AuthorizationMessageRequest) WithZeroKnowledgeProofRequest(proof verifiable.ZeroKnowledgeProofRequest) {
	m.Body.Scope = append(m.Body.Scope, proof)
}

// WithDefaultZKAuth adds authentication request to scope
func (m *AuthorizationMessageRequest) WithDefaultZKAuth(challenge int64) {

	rules := make(map[string]interface{})
	rules["challenge"] = challenge

	authProofRequest := verifiable.ZeroKnowledgeProofRequest{
		Type:      verifiable.ZeroKnowledgeProofType,
		CircuitID: string(circuits.AuthCircuitID),
		Rules:     rules,
	}
	m.Body.Scope = append(m.Body.Scope, authProofRequest)
}

// CreateAuthorizationRequest creates new authorization request message
func CreateAuthorizationRequest(challenge int64, aud, callbackURL string) *AuthorizationMessageRequest {
	var message AuthorizationMessageRequest

	message.Typ = packers.MediaTypePlainMessage
	message.Type = auth.AuthorizationRequestMessageType
	message.Body = AuthorizationMessageRequestBody{
		CallbackURL: callbackURL,
		Audience:    aud,
		Scope:       []verifiable.ZeroKnowledgeProofRequest{},
	}

	message.WithDefaultZKAuth(challenge)

	return &message
}

// VerifyProofs verifies only zk proofs of authorization response message
func VerifyProofs(message iden3comm.Iden3Message) (err error) {

	if message.GetType() != auth.AuthorizationResponseMessageType && message.GetType() != credentials.FetchRequestMessageType {
		return fmt.Errorf("auth lib doesn't support %s message type", message.GetType())
	}
	var authorizationResponseData auth.AuthorizationMessageResponseBody

	switch message.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetBody().(json.RawMessage), &authorizationResponseData)
		if err != nil {
			return err
		}
	case auth.AuthorizationMessageResponseBody:
		authorizationResponseData = message.GetBody().(auth.AuthorizationMessageResponseBody)
	}
	for _, proof := range authorizationResponseData.Scope {
		switch proof.Type {
		case verifiable.ZeroKnowledgeProofType:
			err = proofs.VerifyProof(proof)
			if err != nil {
				return fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
		default:
			return errors.Errorf("unknown proof type %s", proof.Type)
		}
	}
	return nil
}

func ExtractMetadata(proof protocol.ZeroKnowledgeProof) (map[string]interface{}, err error) {
	if message.GetType() != auth.AuthorizationResponseMessageType && message.GetType() != credentials.FetchRequestMessageType {
		return nil, fmt.Errorf("auth lib doesn't support %s message type", message.GetType())
	}
	var authorizationResponseData auth.AuthorizationMessageResponseBody
	switch message.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetBody().(json.RawMessage), &authorizationResponseData)
		if err != nil {
			return nil, err
		}
	case auth.AuthorizationMessageResponseBody:
		authorizationResponseData = message.GetBody().(auth.AuthorizationMessageResponseBody)
	}
	token = &UserToken{}
	token.Scope = map[string]map[string]interface{}{}
	for _, proof := range authorizationResponseData.Scope {
		switch proof.Type {
		case verifiable.ZeroKnowledgeProofType:
			var metadata auth.ProofMetadata
			metadata, err = proofs.ExtractMetadata(proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.Update(string(proof.CircuitID), metadata)

			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}
		default:
			return nil, errors.Errorf("proof type is not supported %s", err)
		}
	}
	return token, nil
}

// ExtractMetadata extract userToken from provided proofs
func ExtractMetadata(message iden3comm.Iden3Message) (token *UserToken, err error) {
	if message.GetType() != auth.AuthorizationResponseMessageType && message.GetType() != credentials.FetchRequestMessageType {
		return nil, fmt.Errorf("auth lib doesn't support %s message type", message.GetType())
	}
	var authorizationResponseData auth.AuthorizationMessageResponseBody
	switch message.GetBody().(type) {
	case json.RawMessage:
		err = json.Unmarshal(message.GetBody().(json.RawMessage), &authorizationResponseData)
		if err != nil {
			return nil, err
		}
	case auth.AuthorizationMessageResponseBody:
		authorizationResponseData = message.GetBody().(auth.AuthorizationMessageResponseBody)
	}
	token = &UserToken{}
	token.Scope = map[string]map[string]interface{}{}
	for _, proof := range authorizationResponseData.Scope {
		switch proof.Type {
		case verifiable.ZeroKnowledgeProofType:
			var metadata auth.ProofMetadata
			metadata, err = proofs.ExtractMetadata(proof)
			if err != nil {
				return nil, fmt.Errorf("proof with type  %s is not valid. %s", proof.Type, err.Error())
			}
			err = token.Update(string(proof.CircuitID), metadata)

			if err != nil {
				return nil, fmt.Errorf("can't provide user token %s", err.Error())
			}
		default:
			return nil, errors.Errorf("proof type is not supported %s", err)
		}
	}
	return token, nil
}

/*
	SERVER issues token after user login. - unapplicable for current stage.

*/

/*
Client - Server:
	Client:
0.1 - user request {AtomicQueryMTP, "age > 23"}
		1. Send token as : POST Body
			- euuerugreg.fdgdfgdfgdfg.ggdfgdfgdf
			- { "payload": dsdsf , "signatures:[ sadasdas]}
	Server:
		1. tokenBytes := r.Read(body)
		2. token :=  jwz.Unmarshal(tokenBytes)
		3. err := token.VerifyZKP() : zkp is verified.
		4. err := token.ParseProofMetadata() metadata is extracted from public signals
					- { token.ID, token.State ,token.CreationTimestamp }
        5. stateTransitionInfo := token.VerifyState(rpcURL)
		6. json.Unmarshall(token.Payload, &iden3comm.ProofResponse{Scope:[ZKPProof]})

AtomicProofRequst:{

}

 - VerifyState
 - VerifyQuery(circuit, rulls)
interface{
	UnmarshalCircuitOutput
	Verify
}

zkpRequest[3].Type = AtomicQueryMTP
zkpRequest[3].CicuitID = AtomicQueryMTP

proof[1].ID=[2].ID

scope:{
	[atmicmtp]: age > 18, ID
	[atomicmtp]: country notin [100, 1000], ID
}

proofResponse:{

}

verify( proofs, requestMessage){
		for each request in requestMessage {
				// find proof for request
 				proofToVerify = proofs[requestId] if not found - error.
				auth.VerifyZKPProof(proof)
			    auth.VerifyQuery(proof, request.rules)

		}
	}

				VerifyQuery( proof,  rules):

						CIRCUITVERIFIER. := auth.ParseProofMetadata(proof)
								AtomiQueryMPT {
									AtomicQueryMTPOutputs
								}
								(c *AtomiQueryMPT)VerifyStates(){

								}
								VerifyRulles(request{}){
								}
								CIRCUITVERIFIER{
									VERIFYSTATES()
									VERIFYRULLES()
								}
						CIRCUITVERIFIER.VerifyStates()
						CIRCUITVERIFIER.VerifyMetadata(rules)

*/
