package proofs

import (
	"os"
	"testing"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
)

func TestVerifyProof(t *testing.T) {

	var err error
	proofMessage := protocol.ZeroKnowledgeProofResponse{ZKProof: types.ZKProof{
		Proof: &types.ProofData{
			A: []string{
				"957698408427964949373649712039920043210974666537246242527666231574736447215",
				"4086301798091555580700861865212439093760939259461303470105592576075967110809",
				"1",
			},
			B: [][]string{
				{
					"17761559932897315893618895130972320113328240504534127684296053239008480650132",
					"5632193781365169642645888319571038406614807943044397798965094551600628234503",
				},
				{
					"1365440307473149802051965484085369690014133594254254856398071522896525497247",
					"9143247083381732337710902360194843027755305930598838459668134140717530368519",
				},
				{
					"1",
					"0",
				}},
			C: []string{
				"16707768020019049851803695616000699953210287095055797633254316035548791886996",
				"20859199949100338932805050654787060104015161388984781255169527105633884420687",
				"1",
			},
			Protocol: "groth16",
		},
		PubSignals: []string{
			"379949150130214723420589610911161895495647789006649785264738141299135414272",
			"18656147546666944484453899241916469544090258810192803949522794490493271005313",
			"1",
			"17339270624307006522829587570402128825147845744601780689258033623056405933706",
			"26599707002460144379092755370384635496563807452878989192352627271768342528",
			"1642074362",
			"106590880073303418818490710639556704462",
			"2",
			"5",
			"840",
			"120",
			"340",
			"509",
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
		},
	}}
	proofMessage.CircuitID = string(circuits.AtomicQueryMTPCircuitID)

	verificationKey, err := os.ReadFile("../testdata/credentialAtomicQueryMTP.json")
	assert.NoError(t, err)

	proofMessage.ID = 1

	err = VerifyProof(proofMessage, verificationKey)
	assert.Nil(t, err)
}
