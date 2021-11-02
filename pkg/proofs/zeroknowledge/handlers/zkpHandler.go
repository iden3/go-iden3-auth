package handlers

import (
	"fmt"
	"github.com/iden3/go-auth/pkg/types"
)

// ZeroKnowledgeProofHandler is handler to check message type
type ZeroKnowledgeProofHandler struct {
	next ProofHandler
}

// Process applies handler logic on provided message
func (h *ZeroKnowledgeProofHandler) Process(m *types.ZeroKnowledgeProof) (err error) {

	if m.Type != types.ZeroKnowledgeProofType {
		return fmt.Errorf("proofs type %s is not supported by ZKP handler", m.Type)
	}
	if h.next != nil {
		err = h.next.Process(m)
	}
	return err
}

// SetNext sets next handler to the chain of handlers
func (h *ZeroKnowledgeProofHandler) SetNext(next ProofHandler) ProofHandler {
	h.next = next
	return h
}
