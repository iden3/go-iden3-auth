package handlers

import "github.com/iden3/go-auth/pkg/types"

type proofHandler interface {
	Process(p *types.ZeroKnowledgeProof) (err error)
	SetNext(proofHandler) proofHandler
}
