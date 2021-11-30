package handlers

import (
	"fmt"
	"github.com/iden3/go-auth/types"
	"github.com/iden3/go-auth/verification"
)

// VerificationHandler is handler to check verification of the provided proof
type VerificationHandler struct {
	next ProofHandler
}

// Process applies handler logic on provided message
func (h *VerificationHandler) Process(m *types.ZeroKnowledgeProof) (err error) {

	err = verification.VerifyProof(*m.ProofData, m.PubSignals, []byte(m.CircuitData.VerificationKey))
	if err != nil {
		return err
	}
	fmt.Println("proofs verified")

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
