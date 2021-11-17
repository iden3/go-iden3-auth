package handlers

import (
	"github.com/iden3/go-auth/types"
)

// ProofHandler is a handler for proof processing
type ProofHandler interface {
	Process(p *types.ZeroKnowledgeProof) (err error)
	SetNext(ProofHandler) ProofHandler
}
