package packer

import (
	"testing"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/communication/auth"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/stretchr/testify/assert"
)

func TestPlainMessagePacker_Pack(t *testing.T) {
	packer := PlainMessagePacker{}

	var message types.AuthorizationMessageRequest
	message.Type = auth.AuthorizationRequestMessageType
	message.Data = types.AuthorizationMessageRequestData{}
	message.Data.Audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	message.Data.CallbackURL = "https://test.com"

	zkpProofRequest := types.ZeroKnowledgeProofRequest{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: circuits.KycBySignaturesCircuitID,
		Rules: map[string]interface{}{
			"challenge": "1234567",
		},
	}
	message.Data.Scope = []types.TypedScope{zkpProofRequest}
	message.WithDefaultZKAuth(1234567)
	msgBytes, err := packer.Pack("application/json", &message)
	t.Log(string(msgBytes))
	assert.Nil(t, err)
	assert.NotEmpty(t, msgBytes)
	m, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.NotEmpty(t, m)

}
func TestPlainMessagePacker_Unpack(t *testing.T) {
	packer := PlainMessagePacker{}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-response/v1","data":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","5816868615164565912277677884704888703982258184820398645933682814085602171910","286312392162647260160287083374160163061246635086990474403590223113720496128"],"proof_data":{"pi_a":["2370534291294441687575434871070063634049522739054135650290327914016792634144","18704664440065881255248484392571034267692380947539795837185393466696768539729","1"],"pi_b":[["1593753415597360514506439944675236073038159742598884104707775208490282580641","15142074894866083200293799148931702287457526593114838706672766340147139402722"],["19117825221840408597122339519717065920080389822558089367138595722092823743944","2706264472260224656022451103720565978368804964791420659255319627595448027435"],["1","0"]],"pi_c":["156766304977057264803138092945401446963129379605822159500567538377014916135","10031227231200820171929683445407743402234929438478965985477678284516420821593","1"],"protocol":""}}]}}`)
	message, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.Equal(t, auth.AuthorizationResponseMessageType, message.GetType())

	err = auth.VerifyProofs(message)
	assert.Nil(t, err)

	token, err := auth.ExtractMetadata(message)
	assert.Nil(t, err)
	assert.Equal(t, "113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj", token.ID)

}
func TestPlainMessagePacker_PackAuthorizationResponse(t *testing.T) {
	packer := PlainMessagePacker{}

	var message types.AuthorizationMessageResponse
	message.Type = auth.AuthorizationResponseMessageType
	message.Data = types.AuthorizationMessageResponseData{}

	zkpProof := types.ZeroKnowledgeProof{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: circuits.AuthCircuitID,
	}

	zkpProof.ProofData = &types.ProofData{
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
	}
	zkpProof.PubSignals = []string{
		"1",
		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
		"286312392162647260160287083374160163061246635086990474403590223113720496128",
	}
	message.Data.Scope = []interface{}{zkpProof}

	msgBytes, err := packer.Pack("application/json", &message)
	assert.Nil(t, err)
	assert.NotEmpty(t, msgBytes)
	m, err := packer.Unpack(msgBytes)

	assert.Nil(t, err)
	assert.NotEmpty(t, m)

}
