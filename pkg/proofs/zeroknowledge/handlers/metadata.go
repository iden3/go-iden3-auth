package handlers

import (
	"encoding/json"
	"errors"
	"github.com/iden3/go-auth/pkg/types"
)

const (
	identifierAttribute string = "user_identifier"
	challengeAttribute  string = "challenge"
)

// MetadataProofHandler is handler to extract metadata of the provided proof
type MetadataProofHandler struct {
	next ProofHandler
}

// Process applies handler logic on provided message
func (h *MetadataProofHandler) Process(m *types.ZeroKnowledgeProof) (err error) {

	proofMetadata := types.ProofMetadata{
		AuthData:       &types.AuthenticationMetadata{},
		AdditionalData: map[string]interface{}{},
	}

	// Use some parser to determine identifier based on circuit schema

	var metaData map[string]int

	err = json.Unmarshal([]byte(m.CircuitData.Metadata), &metaData)
	if err != nil {
		return err
	}
	identifierIndex, ok := metaData[identifierAttribute]
	if !ok {
		return errors.New("no user identifier attribute in provided proof")
	}
	challengeIndex, ok := metaData[challengeAttribute]
	if !ok {
		return errors.New("no user challenge attribute in provided proof")
	}
	proofMetadata.AuthData.UserIdentifier = m.PubSignals[identifierIndex].String()
	proofMetadata.AuthData.AuthenticationChallenge = m.PubSignals[challengeIndex].String()

	// load schema fields and indexes

	for k, v := range metaData {
		if k != identifierAttribute && k != challengeAttribute {
			proofMetadata.AdditionalData[k] = m.PubSignals[v].String()
		}
	}

	m.ProofMetadata = proofMetadata
	// load schema here

	if h.next != nil {
		err = h.next.Process(m)
	}
	return err
}

// SetNext sets next handler to the chain of handlers
func (h *MetadataProofHandler) SetNext(next ProofHandler) ProofHandler {
	h.next = next
	return h
}
