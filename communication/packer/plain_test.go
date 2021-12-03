package packer

import (
	"github.com/iden3/go-iden3-auth/communication/auth"
	types2 "github.com/iden3/go-iden3-auth/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPlainMessagePacker_Pack(t *testing.T) {
	packer := PlainMessagePacker{}

	var message types2.AuthorizationMessageRequest
	message.Type = auth.AuthorizationRequestMessageType
	message.Data = types2.AuthorizationMessageRequestData{}
	message.Data.Audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	message.Data.CallbackURL = "https://test.com"

	zkpProofRequest := types2.ZeroKnowledgeProofRequest{
		Type:      types2.ZeroKnowledgeProofType,
		CircuitID: types2.KycBySignaturesCircuitID,
		Rules: map[string]interface{}{
			"challenge": "1234567",
		},
	}
	message.Data.Scope = []types2.TypedScope{zkpProofRequest}
	message.WithDefaultAuth(1234567)
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

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-request/v1","data":{"callbackUrl":"https://test.com","audience":"1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ","scope":[{"circuit_id":"kycBySignatures","type":"zeroknowledge","rules":{"challenge":"1234567"}}]}}`)
	message, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.Equal(t, auth.AuthorizationRequestMessageType, message.GetType())

}
func TestPlainMessagePacker_PackAuthorizationResponse(t *testing.T) {
	packer := PlainMessagePacker{}

	var message types2.AuthorizationMessageResponse
	message.Type = auth.AuthorizationResponseMessageType
	message.Data = types2.AuthorizationMessageResponseData{}

	zkpProof := types2.ZeroKnowledgeProof{
		Type:      types2.ZeroKnowledgeProofType,
		CircuitID: types2.AuthCircuitID,
	}

	zkpProof.ProofData = &types2.ProofData{
		A: []string{"14146277947056297753840642586002829867111675410988595047766001252156753371528", "14571022849315211248046007113544986624773029852663683182064313232057584750907", "1"},
		B: [][]string{
			{"16643510334478363316178974136322830670001098048711963846055396047727066595515", "10398230582752448515583571758866992012509398625081722188208617704185602394573"},
			{"6754852150473185509183929580585027939167256175425095292505368999953776521762", "4988338043999536569468301597030911639875135237017470300699903062776921637682"},
			{
				"1",
				"0",
			}},
		Protocol: "groth16",
		C: []string{
			"17016608018243685488662035612576776697709541343999980909476169114486580874935", "1344455328868272682523157740509602348889110849570014394831093852006878298645", "1"},
	}
	zkpProof.PubSignals = []string{
		"383481829333688262229762912714748186426235428103586432827469388069546950656",
		"12345",
	}
	message.Data.Scope = []types2.TypedScope{zkpProof}

	msgBytes, err := packer.Pack("application/json", &message)
	t.Log(string(msgBytes))
	assert.Nil(t, err)
	assert.NotEmpty(t, msgBytes)
	m, err := packer.Unpack(msgBytes)

	assert.Nil(t, err)
	assert.NotEmpty(t, m)

}
