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

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-response/v1","data":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["360506537017543098982364518145035624387547643177965411252793105868750389248","12345","12051733342209181702880711377819237050140862582923079913097401558944144010618"],"proof_data":{"pi_a":["18936271973117240691705559585769592974936923569213179030272017872877809039923","18422345941126925346404589344471685526481812474926428421192486541362664918772","1"],"pi_b":[["21330507917605771112737495332384182754017872671331663255035774134477307177657","11462448334617588029347704885403867272225695665465848309095217964693916030466"],["6840720762741964372185603768831031763412571244452731103935719626324813065968","21706573949504402596589372160652940106962129670251783730794239678073827564253"],["1","0"]],"pi_c":["17548802242159422756497011319050257549779839182737330954154562317224853077096","16720285840459139191823107762843332365012723866736056448880671648502165007589","1"],"protocol":"groth16"}}]}}`)
	message, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.Equal(t, auth.AuthorizationResponseMessageType, message.GetType())

	err = auth.Verify(message)
	assert.Nil(t, err)

	token, err := auth.ExtractMetadata(message)
	assert.Nil(t, err)
	assert.Equal(t, "116KTvTKY7cQHDf2yUTkuuUTSfLmsrGYzHhUSFrrXu", token.ID)

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
	message.Data.Scope = []interface{}{zkpProof}

	msgBytes, err := packer.Pack("application/json", &message)
	t.Log(string(msgBytes))
	assert.Nil(t, err)
	assert.NotEmpty(t, msgBytes)
	m, err := packer.Unpack(msgBytes)

	assert.Nil(t, err)
	assert.NotEmpty(t, m)

}
