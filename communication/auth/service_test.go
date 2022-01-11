package auth

import (
	"context"
	"github.com/iden3/go-circuits"
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
		CircuitID: circuits.KycBySignaturesCircuitID,
	}

	zkpProof.ProofData = &types.ProofData{
		A: []string{"10441536817202584897377823144827964642356918402871315490038163167310235469676",
			"3188873104904010906845899057040012497857652125001996465924027367142766788060",
			"1"},
		B: [][]string{{"10259767950868305572343651918722890484304440255374794205464892311274784569874",
			"18113532891970083775734522192028652126404157383671158241782353379080674688210",
		}, {
			"20011188305329655231409527762393912898857036946232895893305954758470171745705",
			"19212224402431449690017436050830610655559646158634403540885275057516508525272",
		}, {
			"1",
			"0",
		}},
		C: []string{"17410066358263445906462947561105622363737416663317734129930901016400750644236",
			"10889346016675221860511647187111664354773325795907973404602900127856769668544",
			"1",
		},
	}
	zkpProof.PubSignals = []string{"12345", "372902514040400364441393275265861152892555341750332828757240276565437644800", "19443506635601976434000063402326775248489014592264899338419890539515181882284", "840", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "372902514040400364441393275265861152892555341750332828757240276565437644800", "19443506635601976434000063402326775248489014592264899338419890539515181882284", "2021", "4", "25"}
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
		CircuitID: circuits.KycBySignaturesCircuitID,
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
		CircuitID: circuits.KycBySignaturesCircuitID,
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
		CircuitID: circuits.KycBySignaturesCircuitID,
		CircuitData: &types.CircuitData{
			ID:              circuits.KycBySignaturesCircuitID,
			Description:     "test",
			VerificationKey: circuits.KycBySignaturesVerificationKey,
			Metadata:        circuits.KycBySignaturesPublicSignalsSchema,
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

	assert.Equal(t, "26592849444054787445766572449338308165040390141345377877344569181291872256", token.Challenge)

}

func TestVerifyMessageWithAuthProof(t *testing.T) {

	var message types.AuthorizationMessageResponse
	message.Type = AuthorizationResponseMessageType
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

	err := Verify(&message)
	assert.Nil(t, err)

	token, err := ExtractMetadata(&message)
	assert.Nil(t, err)
	assert.Equal(t, "18311560525383319719311394957064820091354976310599818797157189568621466950811", token.State)
	assert.Equal(t, "1182P96d4eBnRAUWvGyj5QiPLL5U1TiNyJwcspt478", token.ID)

	state, err := token.VerifyState(context.Background(), os.Getenv("RPC_URL"), "0x035C4DBC897D203483D942696CE1dF5a9f933FcC")
	assert.Nil(t, err)
	assert.Equal(t, true, state.Latest)

}
