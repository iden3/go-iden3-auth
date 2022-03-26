package verification

import (
	"encoding/json"
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/iden3/go-iden3-auth/internal/models"
	"github.com/iden3/go-iden3-auth/types"
)

// VerifyProof performs a verification of zkp  based on verification key and public inputs
func VerifyProof(proof types.ProofData, publicInputs types.PublicInputs, verificationKey []byte) error {

	// 1. cast external proof data to internal model.

	p, err := proof.ToInternalProofData()
	if err != nil {
		return err
	}

	// 2. cast external verification key data to internal model.
	var vk types.VkString
	err = json.Unmarshal(verificationKey, &vk)
	if err != nil {
		return err
	}
	vkKey, err := vk.ToInternalVk()
	if err != nil {
		return err
	}

	// 2. cast external public inputs data to internal model.
	pubSignals, err := publicInputs.ToBigInt()
	if err != nil {
		return err
	}

	return verifyGroth16(vkKey, p, pubSignals)
}

// verifyGroth16 performs the verification the Groth16 zkSNARK proofs
func verifyGroth16(vk *models.Vk, proof models.ProofData, inputs []*big.Int) error {
	if len(inputs)+1 != len(vk.IC) {
		return fmt.Errorf("len(inputs)+1 != len(vk.IC)")
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[i].Cmp(models.R) != -1 {
			return fmt.Errorf("input value is not in the fields")
		}
		vkX = new(bn256.G1).Add(vkX, new(bn256.G1).ScalarMult(vk.IC[i+1], inputs[i]))
	}
	vkX = new(bn256.G1).Add(vkX, vk.IC[0])

	g1 := []*bn256.G1{proof.A, new(bn256.G1).Neg(vk.Alpha), vkX.Neg(vkX), new(bn256.G1).Neg(proof.C)}
	g2 := []*bn256.G2{proof.B, vk.Beta, vk.Gamma, vk.Delta}

	res := bn256.PairingCheck(g1, g2)
	if !res {
		return fmt.Errorf("invalid proofs")
	}
	return nil
}
