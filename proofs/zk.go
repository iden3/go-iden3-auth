package proofs

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
)

// VerifyProof performs protocol proof response verification
func VerifyProof(resp protocol.ZeroKnowledgeProofResponse) (err error) {

	verKey, err := circuits.GetVerificationKey(circuits.CircuitID(resp.CircuitID))
	if err != nil {
		return err
	}
	switch resp.Proof.Protocol {
	case "groth16":
		return VerifyGroth16Proof(verifiable.ZKProof{Proof: resp.Proof, PubSignals: resp.PubSignals}, verKey)
	default:
		return errors.Errorf("%s protocol is not supported", resp.Proof.Protocol)
	}
}
