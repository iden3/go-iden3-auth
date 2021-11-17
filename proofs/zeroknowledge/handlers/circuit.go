package handlers

import (
	"fmt"
	types2 "github.com/iden3/go-auth/types"
)

// CircuitHandler is handler to verify circuit information of provided proof
type CircuitHandler struct {
	SupportedCircuits map[types2.CircuitID]types2.CircuitData
	next              ProofHandler
}

// Process applies handler logic on provided message
func (h *CircuitHandler) Process(m *types2.ZeroKnowledgeProof) (err error) {

	circuitData, ok := h.SupportedCircuits[m.CircuitID]
	if !ok {
		return fmt.Errorf("circuit with ID %s is not supported", m.CircuitID)
	}
	m.CircuitData = &circuitData

	if h.next != nil {
		err = h.next.Process(m)
	}
	return err
}

// SetNext sets next handler to the chain of handlers
func (h *CircuitHandler) SetNext(next ProofHandler) ProofHandler {
	h.next = next
	return h
}