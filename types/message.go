package types

import (
	"encoding/json"
)

// ProtocolMessage is type for protocol messages
type ProtocolMessage string

// Message restricts objects that can be presented as protocol messages
type Message interface {
	GetType() ProtocolMessage
	GetData() interface{}
}

// BasicMessage is structure for message with unknown data format
type BasicMessage struct {
	Type ProtocolMessage `json:"type"`
	Data json.RawMessage `json:"data"`
	Message
}

// GetType returns defined type of BasicMessage
func (m *BasicMessage) GetType() ProtocolMessage {
	return m.Type
}

// GetData returns data of BasicMessage
func (m *BasicMessage) GetData() interface{} {
	return m.Data
}

// AuthorizationMessageRequestData is struct the represents authorization request data
type AuthorizationMessageRequestData struct {
	CallbackURL string       `json:"callbackUrl"`
	Audience    string       `json:"audience"`
	Scope       []TypedScope `json:"scope"`
}

// AuthorizationMessageResponseData is struct the represents authorization response data
type AuthorizationMessageResponseData struct {
	Scope []interface{} `json:"scope"`
}

// TypedScope is interface that restricts objects that can be used for scope in authorization request
type TypedScope interface {
	GetType() ProofType
}

// AuthorizationMessageRequest is struct the represents authentication request message format
type AuthorizationMessageRequest struct {
	Type    ProtocolMessage                 `json:"type"`
	Data    AuthorizationMessageRequestData `json:"data"`
	Message `json:"-"`
}

// GetType returns defined type of AuthorizationMessageRequest
func (m *AuthorizationMessageRequest) GetType() ProtocolMessage {
	return m.Type
}

// GetData returns data of AuthorizationMessageRequest
func (m *AuthorizationMessageRequest) GetData() interface{} {
	return m.Data
}

// WithZeroKnowledgeProofRequest adds zkp proof to scope of request
func (m *AuthorizationMessageRequest) WithZeroKnowledgeProofRequest(proof ZeroKnowledgeProofRequest) {
	m.Data.Scope = append(m.Data.Scope, proof)
}

// WithDefaultAuth adds authentication request to scope
func (m *AuthorizationMessageRequest) WithDefaultAuth(challenge int64) error {

	authRules := AuthenticationRules{
		Challenge: challenge,
		Audience:  m.Data.Audience,
	}
	var rules map[string]interface{}
	rulesBytes, err := json.Marshal(authRules)
	if err != nil {
		return err
	}
	err = json.Unmarshal(rulesBytes, &rules)

	authProofRequest := ZeroKnowledgeProofRequest{
		Type:      ZeroKnowledgeProofType,
		CircuitID: AuthCircuitID,
		Rules:     rules,
	}
	m.Data.Scope = append(m.Data.Scope, authProofRequest)
	return err
}

// AuthorizationMessageResponse is struct the represents authentication response message format
type AuthorizationMessageResponse struct {
	Type    ProtocolMessage                  `json:"type"`
	Data    AuthorizationMessageResponseData `json:"data"`
	Message `json:"-"`
}

// GetType returns defined type of AuthorizationMessage
func (m *AuthorizationMessageResponse) GetType() ProtocolMessage {
	return m.Type
}

// GetData returns data of AuthorizationMessage
func (m *AuthorizationMessageResponse) GetData() interface{} {
	return m.Data
}
