package proofs

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/verification"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
)

// VerifyProof performs groth16 verification
func VerifyProof(resp protocol.ZeroKnowledgeProofResponse) (err error) {

	verKey, err := circuits.GetVerificationKey(circuits.CircuitID(resp.CircuitID))
	if err != nil {
		return err
	}
	err = verification.VerifyProof(verifiable.ZKProof{Proof: resp.Proof, PubSignals: resp.PubSignals}, verKey)
	return err
}
