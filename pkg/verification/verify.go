package verification

import (
	"encoding/json"
	"fmt"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/iden3/go-auth/pkg/types"
	"github.com/iden3/go-circom-prover-verifier/parsers"

	circomTypes "github.com/iden3/go-circom-prover-verifier/types"

	"math/big"
)

// Verify performs a verification of zkp  based on verification key and public inputs
func Verify(proof types.ProofData, publicInputs []*big.Int, verificationKey []byte) error {

	// 1. parse proofs to proofs object with big integers (circom type)

	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	var p circomTypes.Proof
	err = p.UnmarshalJSON(proofBytes)
	if err != nil {
		return err
	}

	// 2. parse inputs to [] string if needed

	vkKey, err := parsers.ParseVk(verificationKey)
	if err != nil {
		return err
	}

	return verify(vkKey, &p, publicInputs)
}

// verify performs the verification the Groth16 zkSNARK proofs
func verify(vk *circomTypes.Vk, proof *circomTypes.Proof, inputs []*big.Int) error {
	if len(inputs)+1 != len(vk.IC) {
		return fmt.Errorf("len(inputs)+1 != len(vk.IC)")
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[i].Cmp(circomTypes.R) != -1 {
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
