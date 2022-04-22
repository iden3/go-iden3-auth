package proofs

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/verification"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol/auth"
	"github.com/pkg/errors"
	"math/big"
)

// public signals attributes
const (
	identifierAttribute string = "userID"
	challengeAttribute  string = "challenge"
	stateAttribute      string = "userState"
)

// VerifyProof performs groth16 verification
func VerifyProof(m *auth.ZeroKnowledgeProof) (err error) {

	if m.Type != verifiable.ZeroKnowledgeProofType {
		return fmt.Errorf("proofs type %s is not zeroknowledge", m.Type)
	}

	c, err := circuits.GetCircuit(m.CircuitID)
	if err != nil {
		return err
	}

	err = verification.VerifyProof(verifiable.ZKProof{
		Proof:      m.ProofData,
		PubSignals: m.PubSignals,
	}, []byte(c.GetVerificationKey()))

	return err
}

// ExtractMetadata extracts proof metadata
func ExtractMetadata(m *auth.ZeroKnowledgeProof) (err error) {

	if m.Type != verifiable.ZeroKnowledgeProofType {
		return fmt.Errorf("proofs type %s is not zeroknowledge", m.Type)
	}

	c, err := circuits.GetCircuit(m.CircuitID)
	if err != nil {
		return err
	}
	proofData, err := parsePublicSignals(m.PubSignals, []byte(c.GetPublicSignalsSchema()))
	if err != nil {
		return err
	}
	m.ProofMetadata = proofData

	return err
}

func parsePublicSignals(signals []string, schema []byte) (auth.ProofMetadata, error) {
	proofMetadata := auth.ProofMetadata{
		AuthData:       &auth.AuthenticationMetadata{},
		AdditionalData: map[string]interface{}{},
	}

	// Use some parser to determine identifier based on circuit schema

	var metaData map[string]int

	err := json.Unmarshal(schema, &metaData)
	if err != nil {
		return auth.ProofMetadata{}, err
	}
	identifierIndex, ok := metaData[identifierAttribute]
	if !ok {
		return auth.ProofMetadata{}, errors.New("no user identifier attribute in provided proof")
	}
	stateIndex, ok := metaData[stateAttribute]
	if ok {
		proofMetadata.AuthData.UserState = signals[stateIndex]
	}
	challengeIndex, ok := metaData[challengeAttribute]
	if !ok {
		return auth.ProofMetadata{}, errors.New("no user challenge attribute in provided proof")
	}

	proofMetadata.AuthData.UserIdentifier, err = convertID(signals[identifierIndex])
	if err != nil {
		return auth.ProofMetadata{}, err
	}

	proofMetadata.AuthData.AuthenticationChallenge = signals[challengeIndex]

	// load schema fields and indexes
	for k, v := range metaData {
		if k != identifierAttribute && k != challengeAttribute {
			proofMetadata.AdditionalData[k] = signals[v]
		}
	}
	return proofMetadata, err
}
func convertID(_id string) (string, error) {
	idInt, ok := new(big.Int).SetString(_id, 10)
	if !ok {
		return "", errors.New("id is not a big int")
	}
	elemBytes := merkletree.NewElemBytesFromBigInt(idInt)
	id, err := core.IDFromBytes(elemBytes[:31])
	if !ok {
		return "", err
	}
	return id.String(), nil
}
