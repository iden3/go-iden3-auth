package proofs

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyProof(t *testing.T) {

	t.Skip("broken")
	var err error
	proofMessage := protocol.ZeroKnowledgeProofResponse{}
	proofMessage.CircuitID = string(circuits.AuthCircuitID)

	proofMessage.Proof = &verifiable.ProofData{
		A: []string{
			"2370534291294441687575434871070063634049522739054135650290327914016792634144",
			"18704664440065881255248484392571034267692380947539795837185393466696768539729",
			"1",
		},
		B: [][]string{
			{
				"1593753415597360514506439944675236073038159742598884104707775208490282580641",
				"15142074894866083200293799148931702287457526593114838706672766340147139402722",
			},
			{
				"19117825221840408597122339519717065920080389822558089367138595722092823743944",
				"2706264472260224656022451103720565978368804964791420659255319627595448027435",
			},
			{
				"1",
				"0",
			}},
		C: []string{
			"156766304977057264803138092945401446963129379605822159500567538377014916135",
			"10031227231200820171929683445407743402234929438478965985477678284516420821593",
			"1",
		},
		Protocol: "groth16",
	}
	proofMessage.PubSignals = []string{
		"1",
		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
		"286312392162647260160287083374160163061246635086990474403590223113720496128",
	}
	proofMessage.ID = "1"

	err = VerifyProof(proofMessage)
	assert.Nil(t, err)
}
