package proofs

import (
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
)

// VerifyProof performs protocol proof response verification
func VerifyProof(resp protocol.ZeroKnowledgeProofResponse, verificationKey []byte) (err error) {
	switch resp.Proof.Protocol {
	case "groth16":
		return VerifyGroth16Proof(verifiable.ZKProof{Proof: resp.Proof, PubSignals: resp.PubSignals}, verificationKey)
	default:
		return errors.Errorf("%s protocol is not supported", resp.Proof.Protocol)
	}
}
