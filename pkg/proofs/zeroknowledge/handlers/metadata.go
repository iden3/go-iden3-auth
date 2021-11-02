package handlers

import (
	"encoding/json"
	"errors"
	"github.com/iden3/go-auth/pkg/types"
)

const (
	IdentifierAttribute string = "user_identifier"
	ChallengeAttribute  string = "challenge"
)

// MetadataProofHandler is handler to extract metadata of the provided proof
type MetadataProofHandler struct {
	next proofHandler
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
	identifierIndex, ok := metaData[IdentifierAttribute]
	if !ok {
		return errors.New("no user identifier attribute in provided proof")
	}
	challengeIndex, ok := metaData[ChallengeAttribute]
	if !ok {
		return errors.New("no user challenge attribute in provided proof")
	}
	proofMetadata.AuthData.UserIdentifier = m.PubSignals[identifierIndex].String()
	proofMetadata.AuthData.AuthenticationChallenge = m.PubSignals[challengeIndex].String()

	// load schema fields and indexes

	for k, v := range metaData {
		if k != IdentifierAttribute && k != ChallengeAttribute {
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
func (h *MetadataProofHandler) SetNext(next proofHandler) proofHandler {
	h.next = next
	return h
}
