package verification

import (
	"github.com/iden3/go-auth/circuits"
	"github.com/iden3/go-circom-prover-verifier/parsers"
	types2 "github.com/iden3/go-circom-prover-verifier/types"
	"github.com/iden3/go-circom-prover-verifier/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerify(t *testing.T) {
	// verify the proofs
	vkJSON := []byte(circuits.KYCBySignatureVerificationKey)

	publicJSON := []byte(`["411744492472830263284610159093112301866082562595864436469836164448155795456","12345","123776615674577205629582240968408410063074486679712932519574537196926599168","11688539338838797595201345228132404230382121068811390693927054959014251630145","840","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","123776615674577205629582240968408410063074486679712932519574537196926599168","11688539338838797595201345228132404230382121068811390693927054959014251630145","2021","4","25","18"]`)

	proofJSON := []byte(`{"pi_a":"1d0d50f3df112a8d63fc899f900aa074f7eef2cd8efacf9d5cfee68734289f3a26de558d575bafd06ca5b6b5944d19877e5ea5f3c70c39f855e06069589c835c","pi_b":"2850c86effe287d308edbc711d0340dfae447cf1da1fcdcea93c0619ad73eeae02a0e91a72b7334da417160476ade6bb09d7631da7d76e991f49b59d3ccdd43e2cc4c23b8937a172ad9b3e825a979fce9239a7d5c3eaf3a44496005b6f3d59a6248dae2b3c124f025877062bbf90fbaff48634584c8065c6c14765bd97947e54","pi_c":"242cb3ab3c64530f69303a64eaf74ffa42511b7af16e29189070258d462346491fa67f85df1c16215540e932c85f626fa8a11fb21f14cb12b7b925041c8842a6"}`)

	public, err := parsers.ParsePublicSignals(publicJSON)
	require.Nil(t, err)

	var proof types2.Proof
	err = proof.UnmarshalJSON(proofJSON)

	require.Nil(t, err)
	vk, err := parsers.ParseVk(vkJSON)
	require.Nil(t, err)

	res := verifier.Verify(vk, &proof, public)
	assert.True(t, res)
}
