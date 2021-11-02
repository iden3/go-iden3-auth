package auth

import (
	"github.com/iden3/go-auth/pkg/circuits"
	"github.com/iden3/go-auth/pkg/types"
	"github.com/iden3/go-auth/pkg/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerify(t *testing.T) {

	var message types.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
	message.Data = types.AuthorizationMessageResponseData{}

	signalsString := []string{
		"411744492472830263284610159093112301866082562595864436469836164448155795456",
		"12345",
		"123776615674577205629582240968408410063074486679712932519574537196926599168",
		"11688539338838797595201345228132404230382121068811390693927054959014251630145",
		"840",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"123776615674577205629582240968408410063074486679712932519574537196926599168",
		"11688539338838797595201345228132404230382121068811390693927054959014251630145",
		"2021",
		"4",
		"25",
		"18",
	}
	signalsBigInt, err := utils.ArrayStringToBigInt(signalsString)
	assert.Nil(t, err)
	zkpProof := types.ZeroKnowledgeProof{
		Type:       types.ZeroKnowledgeProofType,
		CircuitID:  types.KycBySignaturesCircuitID,
		PubSignals: signalsBigInt,
		ProofData: &types.ProofData{
			A: "1d0d50f3df112a8d63fc899f900aa074f7eef2cd8efacf9d5cfee68734289f3a26de558d575bafd06ca5b6b5944d19877e5ea5f3c70c39f855e06069589c835c",
			B: "2850c86effe287d308edbc711d0340dfae447cf1da1fcdcea93c0619ad73eeae02a0e91a72b7334da417160476ade6bb09d7631da7d76e991f49b59d3ccdd43e2cc4c23b8937a172ad9b3e825a979fce9239a7d5c3eaf3a44496005b6f3d59a6248dae2b3c124f025877062bbf90fbaff48634584c8065c6c14765bd97947e54",
			C: "242cb3ab3c64530f69303a64eaf74ffa42511b7af16e29189070258d462346491fa67f85df1c16215540e932c85f626fa8a11fb21f14cb12b7b925041c8842a6",
		},
	}
	message.Data.Scope = []types.TypedScope{zkpProof}

	err = Verify(&message)
	assert.Nil(t, err)
}

func TestVerifyWrongMessage(t *testing.T) {

	var message types.AuthorizationMessageRequest
	message.Type = AuthorizationRequestMessageType
	message.Data = types.AuthorizationMessageRequestData{}

	zkpProofRequest := types.ZeroKnowledgeProofRequest{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.KycBySignaturesCircuitID,
		Rules:     map[string]interface{}{},
	}
	message.Data.Scope = []types.TypedScope{zkpProofRequest}

	err := Verify(&message)

	assert.NotNil(t, err)
}

func TestCreateAuthorizationRequest(t *testing.T) {

	aud := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	zkpProofRequest := types.ZeroKnowledgeProofRequest{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.KycBySignaturesCircuitID,
		Rules: map[string]interface{}{
			"challenge":        12345678,
			"countryBlacklist": []int{840},
			"currentYear":      2021,
			"currentMonth":     9,
			"currentDay":       28,
			"minAge":           18,
			"audience":         aud,
			"allowedIssuers": []string{
				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
			},
		},
	}

	request := CreateAuthorizationRequest(aud, "https://test.com/callback")
	err := request.WithDefaultAuth(10)
	assert.Nil(t, err)

	request.WithZeroKnowledgeProofRequest(zkpProofRequest)

	assert.Equal(t, 2, len(request.Data.Scope))
}

func TestExtractData(t *testing.T) {

	var message types.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
	message.Data = types.AuthorizationMessageResponseData{}

	signalsString := []string{
		"411744492472830263284610159093112301866082562595864436469836164448155795456",
		"12345",
		"123776615674577205629582240968408410063074486679712932519574537196926599168",
		"11688539338838797595201345228132404230382121068811390693927054959014251630145",
		"840",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"123776615674577205629582240968408410063074486679712932519574537196926599168",
		"11688539338838797595201345228132404230382121068811390693927054959014251630145",
		"2021",
		"4",
		"25",
		"18",
	}
	signalsBigInt, err := utils.ArrayStringToBigInt(signalsString)

	zkpProof := types.ZeroKnowledgeProof{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.KycBySignaturesCircuitID,
		CircuitData: &types.CircuitData{
			ID:              types.KycBySignaturesCircuitID,
			Description:     "test",
			VerificationKey: circuits.KYCBySignatureVerificationKey,
			Metadata:        circuits.KYCBySignaturePublicSignalsSchema,
		},
		PubSignals: signalsBigInt,
		ProofData: &types.ProofData{
			A: "1d0d50f3df112a8d63fc899f900aa074f7eef2cd8efacf9d5cfee68734289f3a26de558d575bafd06ca5b6b5944d19877e5ea5f3c70c39f855e06069589c835c",
			B: "2850c86effe287d308edbc711d0340dfae447cf1da1fcdcea93c0619ad73eeae02a0e91a72b7334da417160476ade6bb09d7631da7d76e991f49b59d3ccdd43e2cc4c23b8937a172ad9b3e825a979fce9239a7d5c3eaf3a44496005b6f3d59a6248dae2b3c124f025877062bbf90fbaff48634584c8065c6c14765bd97947e54",
			C: "242cb3ab3c64530f69303a64eaf74ffa42511b7af16e29189070258d462346491fa67f85df1c16215540e932c85f626fa8a11fb21f14cb12b7b925041c8842a6",
		},
	}
	message.Data.Scope = []types.TypedScope{zkpProof}

	token, err := ExtractMetadata(&message)
	assert.Nil(t, err)

	assert.Equal(t, "12345", token.Challenge)

}
