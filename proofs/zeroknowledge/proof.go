package zeroknowledge

import (
	circuits2 "github.com/iden3/go-auth/circuits"
	handlers2 "github.com/iden3/go-auth/proofs/zeroknowledge/handlers"
	types2 "github.com/iden3/go-auth/types"
)

var supportedCircuits = map[types2.CircuitID]types2.CircuitData{
	types2.KycBySignaturesCircuitID: {
		ID:              types2.KycBySignaturesCircuitID,
		Description:     "circuit for kyc claims verification",
		VerificationKey: circuits2.KYCBySignatureVerificationKey,
		Metadata:        circuits2.KYCBySignaturePublicSignalsSchema,
	},
	types2.AuthCircuitID: {
		ID:              types2.AuthCircuitID,
		Description:     "circuit for verification of  basic authentication",
		VerificationKey: circuits2.AuthenticationVerificationKey,
		Metadata:        circuits2.AuthenticationPublicSignalsSchema,
	},
}

// VerifyProof performs groth16 verification
func VerifyProof(m *types2.ZeroKnowledgeProof) (err error) {

	zkp := &handlers2.ZeroKnowledgeProofHandler{}

	ch := &handlers2.CircuitHandler{
		SupportedCircuits: supportedCircuits,
	}
	zkp.SetNext(ch)

	vh := &handlers2.VerificationHandler{}
	ch.SetNext(vh)

	return zkp.Process(m)
}

// ExtractMetadata extracts proof metadata
func ExtractMetadata(m *types2.ZeroKnowledgeProof) (err error) {

	zkp := &handlers2.ZeroKnowledgeProofHandler{}

	ch := &handlers2.CircuitHandler{
		SupportedCircuits: supportedCircuits,
	}

	mph := &handlers2.MetadataProofHandler{}

	zkp.SetNext(ch).SetNext(mph)

	err = zkp.Process(m)
	return err
}
