package credentials

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyCredentialFetchRequest(t *testing.T) {

	var message types.CredentialFetchRequest
	message.Type = CredentialFetchRequestMessageType
	message.Data = types.CredentialFetchRequestMessageData{ClaimID: "992fc184-c902-4f9a-af62-b383cc5e1eb4", Schema: "KYCAgeCredential"}

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

	err := VerifyCredentialFetchRequest(&message)
	assert.Nil(t, err)
}

func TestExtractDataFromCredentialFetchRequest(t *testing.T) {

	var message types.CredentialFetchRequest
	message.Type = CredentialFetchRequestMessageType
	message.Data = types.CredentialFetchRequestMessageData{ClaimID: "992fc184-c902-4f9a-af62-b383cc5e1eb4", Schema: "KYCAgeCredential"}

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

	token, err := ExtractMetadataFromCredentialFetchRequest(&message)
	assert.Nil(t, err)
	assert.Equal(t, "1", token.Challenge)
	assert.Equal(t, "992fc184-c902-4f9a-af62-b383cc5e1eb4", token.ClaimID)
	assert.Equal(t, "KYCAgeCredential", token.ClaimSchema)

}