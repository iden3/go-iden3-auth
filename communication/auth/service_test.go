package auth

import (
	"context"
	"github.com/iden3/go-iden3-auth/circuits"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestVerify(t *testing.T) {

	var message types.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
	message.Data = types.AuthorizationMessageResponseData{}

	zkpProof := types.ZeroKnowledgeProof{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.KycBySignaturesCircuitID,
	}
	zkpProof.ProofData = &types.ProofData{
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
	message.Data.Scope = []interface{}{zkpProof}

	err := Verify(&message)
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

	zkpProof := types.ZeroKnowledgeProof{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.KycBySignaturesCircuitID,
		CircuitData: &types.CircuitData{
			ID:              types.KycBySignaturesCircuitID,
			Description:     "test",
			VerificationKey: circuits.KYCBySignatureVerificationKey,
			Metadata:        circuits.KYCBySignaturePublicSignalsSchema,
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
	zkpProof.ProofData = &types.ProofData{
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

	message.Data.Scope = []interface{}{zkpProof}
	token, err := ExtractMetadata(&message)
	assert.Nil(t, err)

	assert.Equal(t, "12345", token.Challenge)

}

func TestVerifyMessageWithAuthProof(t *testing.T) {

	var message types.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
	message.Data = types.AuthorizationMessageResponseData{}

	zkpProof := types.ZeroKnowledgeProof{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.AuthCircuitID,
	}

	zkpProof.ProofData = &types.ProofData{
		A: []string{
			"18936271973117240691705559585769592974936923569213179030272017872877809039923",
			"18422345941126925346404589344471685526481812474926428421192486541362664918772",
			"1"},
		B: [][]string{
			{
				"21330507917605771112737495332384182754017872671331663255035774134477307177657",
				"11462448334617588029347704885403867272225695665465848309095217964693916030466",
			},
			{
				"6840720762741964372185603768831031763412571244452731103935719626324813065968",
				"21706573949504402596589372160652940106962129670251783730794239678073827564253",
			},
			{
				"1",
				"0",
			}},
		C: []string{
			"17548802242159422756497011319050257549779839182737330954154562317224853077096",
			"16720285840459139191823107762843332365012723866736056448880671648502165007589",
			"1",
		},
	}
	zkpProof.PubSignals = []string{
		"360506537017543098982364518145035624387547643177965411252793105868750389248",
		"12345",
		"12051733342209181702880711377819237050140862582923079913097401558944144010618",
	}
	message.Data.Scope = []interface{}{zkpProof}

	err := Verify(&message)
	assert.Nil(t, err)

	token, err := ExtractMetadata(&message)
	assert.Nil(t, err)
	assert.Equal(t, "12051733342209181702880711377819237050140862582923079913097401558944144010618", token.State)
	assert.Equal(t, "116KTvTKY7cQHDf2yUTkuuUTSfLmsrGYzHhUSFrrXu", token.ID)

	state, err := token.VerifyState(context.Background(), os.Getenv("RPC_URL"), "0x09872d45c8109FC85478827967B6fEa0f59C05c2")
	assert.Nil(t, err)
	assert.Equal(t, true, state.Latest)

}
