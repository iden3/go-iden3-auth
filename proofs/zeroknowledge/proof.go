package zeroknowledge

import (
	"github.com/iden3/go-auth/circuits"
	"github.com/iden3/go-auth/proofs/zeroknowledge/handlers"
	types "github.com/iden3/go-auth/types"
)

var supportedCircuits = map[types.CircuitID]types.CircuitData{
	types.KycBySignaturesCircuitID: {
		ID:              types.KycBySignaturesCircuitID,
		Description:     "circuit for kyc claims verification",
		VerificationKey: circuits.KYCBySignatureVerificationKey,
		Metadata:        circuits.KYCBySignaturePublicSignalsSchema,
	},
	types.AuthCircuitID: {
		ID:              types.AuthCircuitID,
		Description:     "circuit for verification of  basic authentication",
		VerificationKey: circuits.AuthenticationVerificationKey,
		Metadata:        circuits.AuthenticationPublicSignalsSchema,
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
	ch.SetNext(mph)
	zkp.SetNext(ch)

	err = zkp.Process(m)
	return err
}
