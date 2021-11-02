package zeroknowledge

import (
	"github.com/iden3/go-auth/pkg/types"
	"github.com/iden3/go-auth/pkg/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyProof(t *testing.T) {

	var err error
	proofMessage := &types.ZeroKnowledgeProof{}
	proofMessage.CircuitID = types.KycBySignaturesCircuitID
	proofMessage.ProofData = &types.ProofData{
		A: "0e830bfd19abe5a098f4aab0f58a503dc8a89be5668c1ff3e17e1135d7a761e6223dfe8db4e1084f7dc59263ff087587962850471e30ed6ac9ffe062bd14ca6b",
		B: "2b1a65ab8e9ece2a9afeb54952d516a7af2610f5d4990f061c718742e9b8cef82da9ec98f3bfe88564070a13de75c6a484b878680626c840e230db2860a1317f15263adca7388ad6e77bd579e44e27315b86700a3b5a19d9fcb7b7af45529cca276b3183260f4543eb92d9baa4c5ee37ac46cfe16d48253c93a792a603af0517",
		C: "28dff22778c6bccbe9642f3e8f6fbdf5c6a98d1c59a63f4e04a7e4d0730056cc2e54b516bc3e770e0f5923496157a645aff3ad15b65268f869a14cc6ca425331",
	}

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
	proofMessage.PubSignals, err = utils.ArrayStringToBigInt(signalsString)
	assert.Nil(t, err)
	proofMessage.Type = "zeroknowledge"

	err = VerifyProof(proofMessage)
	assert.Nil(t, err)

	err = ExtractMetadata(proofMessage)
	assert.Nil(t, err)
	assert.NotNil(t, proofMessage.AuthData)

}
