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

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-response/v1","data":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["371135506535866236563870411357090963344408827476607986362864968105378316288","12345","16751774198505232045539489584666775489135471631443877047826295522719290880931"],"proof_data":{"pi_a":["8286889681087188684411199510889276918687181609540093440568310458198317956303","20120810686068956496055592376395897424117861934161580256832624025185006492545","1"],"pi_b":[["8781021494687726640921078755116610543888920881180197598360798979078295904948","19202155147447713148677957576892776380573753514701598304555554559013661311518"],["15726655173394887666308034684678118482468533753607200826879522418086507576197","16663572050292231627606042532825469225281493999513959929720171494729819874292"],["1","0"]],"pi_c":["9723779257940517259310236863517792034982122114581325631102251752415874164616","3242951480985471018890459433562773969741463856458716743271162635077379852479","1"],"protocol":"groth16"}}]}}`)
	message, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.Equal(t, auth.AuthorizationResponseMessageType, message.GetType())

	err = auth.Verify(message)
	assert.Nil(t, err)

	token, err := auth.ExtractMetadata(message)
	assert.Nil(t, err)
	assert.Equal(t, "11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s", token.ID)

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
