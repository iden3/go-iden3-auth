package zeroknowledge

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/proofs/zeroknowledge/handlers"
	types "github.com/iden3/go-iden3-auth/types"
)

var supportedCircuits = map[circuits.CircuitID]types.CircuitData{
	circuits.KycBySignaturesCircuitID: {
		ID:              circuits.KycBySignaturesCircuitID,
		Description:     "circuit for kyc claims verification",
		VerificationKey: circuits.KycBySignaturesVerificationKey,
		Metadata:        circuits.KycPublicSignalsSchema,
	},
	circuits.AuthCircuitID: {
		ID:              circuits.AuthCircuitID,
		Description:     "circuit for verification of  basic authentication",
		VerificationKey: circuits.AuthenticationVerificationKey,
		Metadata:        circuits.AuthenticationPublicSignalsSchema,
	},
	circuits.AtomicQueryCircuitID: {
		ID:              circuits.AtomicQueryCircuitID,
		Description:     "circuit for atomic query on standard iden3 credential",
		VerificationKey: circuits.AtomicQueryVerificationKey,
		Metadata:        circuits.AtomicQueryPublicSignalsSchema,
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
