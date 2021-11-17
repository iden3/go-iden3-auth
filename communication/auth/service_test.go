package auth

import (
	circuits2 "github.com/iden3/go-auth/circuits"
	types2 "github.com/iden3/go-auth/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerify(t *testing.T) {

	var message types2.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
	message.Data = types2.AuthorizationMessageResponseData{}

	zkpProof := types2.ZeroKnowledgeProof{
		Type:      types2.ZeroKnowledgeProofType,
		CircuitID: types2.KycBySignaturesCircuitID,
	}
	zkpProof.ProofData = &types2.ProofData{
		A: []string{"15410252994758206156331933443865902387659457159831652500594192431349076893658",
			"20150829872771081060142254046116588090324284033366663360366174697329414878949",
			"1"},
		B: [][]string{{"9417153075860115376893693247142868897300054298656960914587138216866082643706",
			"10202816620941554744739718000741718724240818496129635422271960203010394413915",
		}, {"15503138617167966595249072003849677537923997283726290430496888985000900792650",
			"6173958614668002844023250887062625456639056306855696879145959593623787348506",
		}, {
			"1",
			"0",
		}},
		C: []string{
			"14084349531001200150970271267870661180690655641091539571582685666559667846160",
			"6506935406401708938070550600218341978561747347886649538986407400386963731317",
			"1",
		},
	}
	zkpProof.PubSignals = []string{
		"26592849444054787445766572449338308165040390141345377877344569181291872256",
		"12345",
		"164414642845063686862221124543185217840281790633605788367384240953047711744",
		"20826763141600863538041346956386832863527621891653741934199228821528372364336",
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
		"164414642845063686862221124543185217840281790633605788367384240953047711744",
		"20826763141600863538041346956386832863527621891653741934199228821528372364336",
		"2021",
		"4",
		"25",
		"18",
	}
	message.Data.Scope = []types2.TypedScope{zkpProof}

	err := Verify(&message)
	assert.Nil(t, err)
}

func TestVerifyWrongMessage(t *testing.T) {

	var message types2.AuthorizationMessageRequest
	message.Type = AuthorizationRequestMessageType
	message.Data = types2.AuthorizationMessageRequestData{}

	zkpProofRequest := types2.ZeroKnowledgeProofRequest{
		Type:      types2.ZeroKnowledgeProofType,
		CircuitID: types2.KycBySignaturesCircuitID,
		Rules:     map[string]interface{}{},
	}
	message.Data.Scope = []types2.TypedScope{zkpProofRequest}

	err := Verify(&message)

	assert.NotNil(t, err)
}

func TestCreateAuthorizationRequest(t *testing.T) {

	aud := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	zkpProofRequest := types2.ZeroKnowledgeProofRequest{
		Type:      types2.ZeroKnowledgeProofType,
		CircuitID: types2.KycBySignaturesCircuitID,
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

	var message types2.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
	message.Data = types2.AuthorizationMessageResponseData{}

	zkpProof := types2.ZeroKnowledgeProof{
		Type:      types2.ZeroKnowledgeProofType,
		CircuitID: types2.KycBySignaturesCircuitID,
		CircuitData: &types2.CircuitData{
			ID:              types2.KycBySignaturesCircuitID,
			Description:     "test",
			VerificationKey: circuits2.KYCBySignatureVerificationKey,
			Metadata:        circuits2.KYCBySignaturePublicSignalsSchema,
		},
	}
	zkpProof.PubSignals = []string{
		"26592849444054787445766572449338308165040390141345377877344569181291872256",
		"12345",
		"164414642845063686862221124543185217840281790633605788367384240953047711744",
		"20826763141600863538041346956386832863527621891653741934199228821528372364336",
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
		"164414642845063686862221124543185217840281790633605788367384240953047711744",
		"20826763141600863538041346956386832863527621891653741934199228821528372364336",
		"2021",
		"4",
		"25",
		"18",
	}
	zkpProof.ProofData = &types2.ProofData{
		A: []string{"15410252994758206156331933443865902387659457159831652500594192431349076893658",
			"20150829872771081060142254046116588090324284033366663360366174697329414878949",
			"1"},
		B: [][]string{{"9417153075860115376893693247142868897300054298656960914587138216866082643706",
			"10202816620941554744739718000741718724240818496129635422271960203010394413915",
		}, {"15503138617167966595249072003849677537923997283726290430496888985000900792650",
			"6173958614668002844023250887062625456639056306855696879145959593623787348506",
		}, {
			"1",
			"0",
		}},
		C: []string{
			"14084349531001200150970271267870661180690655641091539571582685666559667846160",
			"6506935406401708938070550600218341978561747347886649538986407400386963731317",
			"1",
		},
	}

	message.Data.Scope = []types2.TypedScope{zkpProof}
	token, err := ExtractMetadata(&message)
	assert.Nil(t, err)

	assert.Equal(t, "12345", token.Challenge)

}

func TestVerifyMessageWithAuthProof(t *testing.T) {

	var message types2.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
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
		C: []string{
			"17016608018243685488662035612576776697709541343999980909476169114486580874935", "1344455328868272682523157740509602348889110849570014394831093852006878298645", "1"},
	}
	zkpProof.PubSignals = []string{
		"383481829333688262229762912714748186426235428103586432827469388069546950656",
		"12345",
	}
	message.Data.Scope = []types2.TypedScope{zkpProof}

	err := Verify(&message)
	assert.Nil(t, err)
}
