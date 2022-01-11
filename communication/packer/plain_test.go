package packer

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/communication/auth"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/stretchr/testify/assert"
	"testing"
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

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-response/v1","data":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`)
	message, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.Equal(t, auth.AuthorizationResponseMessageType, message.GetType())

	err = auth.Verify(message)
	assert.Nil(t, err)

	token, err := auth.ExtractMetadata(message)
	assert.Nil(t, err)
	assert.Equal(t, "1182P96d4eBnRAUWvGyj5QiPLL5U1TiNyJwcspt478", token.ID)

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
			"11130843150540789299458990586020000719280246153797882843214290541980522375072",
			"1300841912943781723022032355836893831132920783788455531838254465784605762713",
			"1"},
		B: [][]string{
			{
				"20615768536988438336537777909042352056392862251785722796637590212160561351656",
				"10371144806107778890538857700855108667622042215096971747203105997454625814080",
			},
			{
				"19598541350804478549141207835028671111063915635580679694907635914279928677812",
				"15264553045517065669171584943964322117397645147006909167427809837929458012913",
			},
			{
				"1",
				"0",
			}},
		C: []string{
			"16443309279825508893086251290003936935077348754097470818523558082502364822049",
			"2984180227766048100510120407150752052334571876681304999595544138155611963273",
			"1",
		},
	}
	zkpProof.PubSignals = []string{
		"1",
		"18311560525383319719311394957064820091354976310599818797157189568621466950811",
		"323416925264666217617288569742564703632850816035761084002720090377353297920",
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
