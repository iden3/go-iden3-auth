package handlers

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/iden3/go-iden3-auth/verification"
)

// VerificationHandler is handler to check verification of the provided proof
type VerificationHandler struct {
	next ProofHandler
}

// Process applies handler logic on provided message
func (h *VerificationHandler) Process(m *types.ZeroKnowledgeProof) (err error) {

	key, err := circuits.GetVerificationKey(m.CircuitID)
	if err != nil {
		return err
	}
	err = verification.VerifyProof(*m.ProofData, m.PubSignals, key)
	if err != nil {
		return err
	}
	if h.next != nil {
		err = h.next.Process(m)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetNext sets next handler to the chain of handlers
func (h *VerificationHandler) SetNext(next ProofHandler) ProofHandler {
	h.next = next
	return h
}
