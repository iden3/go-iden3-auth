package zeroknowledge

import (
	"github.com/iden3/go-auth/pkg/circuits"
	handlers "github.com/iden3/go-auth/pkg/proofs/zeroknowledge/handlers"
	"github.com/iden3/go-auth/pkg/types"
)

var supportedCircuits = map[types.CircuitID]types.CircuitData{
	types.KycBySignaturesCircuitID: {
		ID:              types.KycBySignaturesCircuitID,
		Description:     "circuit for kyc claims verification",
		VerificationKey: circuits.KYCBySignatureVerificationKey,
		Metadata:        circuits.KYCBySignaturePublicSignalsSchema,
	},
}

// VerifyProof performs groth16 verification
func VerifyProof(m *types.ZeroKnowledgeProof) (err error) {

	zkp := &handlers.ZeroKnowledgeProofHandler{}

	ch := &handlers.CircuitHandler{
		SupportedCircuits: supportedCircuits,
	}
	zkp.SetNext(ch)

	vh := &handlers.VerificationHandler{}
	ch.SetNext(vh)

	return zkp.Process(m)
}

// ExtractMetadata extracts proof metadata
func ExtractMetadata(m *types.ZeroKnowledgeProof) (err error) {

	zkp := &handlers.ZeroKnowledgeProofHandler{}

	ch := &handlers.CircuitHandler{
		SupportedCircuits: supportedCircuits,
	}

	mph := &handlers.MetadataProofHandler{}

	zkp.SetNext(ch).SetNext(mph)

	err = zkp.Process(m)
	return err
}
