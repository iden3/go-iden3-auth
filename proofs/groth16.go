package proofs

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-schema-processor/verifiable"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// r is the mod of the finite field
const r string = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

// proofPairingData describes three components of zkp proof in bn256 format.
type proofPairingData struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
}

// vk is the Verification Key data structure in bn256 format.
type vk struct {
	Alpha *bn256.G1
	Beta  *bn256.G2
	Gamma *bn256.G2
	Delta *bn256.G2
	IC    []*bn256.G1
}

// vkJSON is the Verification Key data structure in string format (from json).
type vkJSON struct {
	Alpha []string   `json:"vk_alpha_1"`
	Beta  [][]string `json:"vk_beta_2"`
	Gamma [][]string `json:"vk_gamma_2"`
	Delta [][]string `json:"vk_delta_2"`
	IC    [][]string `json:"IC"`
}

// VerifyGroth16Proof performs a verification of zkp  based on verification key and public inputs
func VerifyGroth16Proof(zkProof verifiable.ZKProof, verificationKey []byte) error {

	// 1. cast external proof data to internal model.
	p, err := parseProofData(*zkProof.Proof)
	if err != nil {
		return err
	}

	// 2. cast external verification key data to internal model.
	var vkStr vkJSON
	err = json.Unmarshal(verificationKey, &vkStr)
	if err != nil {
		return err
	}
	vkKey, err := parseVK(vkStr)
	if err != nil {
		return err
	}

	// 2. cast external public inputs data to internal model.
	pubSignals, err := stringsToArrayBigInt(zkProof.PubSignals)
	if err != nil {
		return err
	}

	return verifyGroth16(vkKey, p, pubSignals)
}

// verifyGroth16 performs the verification the Groth16 zkSNARK proofs
func verifyGroth16(vk *vk, proof proofPairingData, inputs []*big.Int) error {
	if len(inputs)+1 != len(vk.IC) {
		return fmt.Errorf("len(inputs)+1 != len(vk.IC)")
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		v, _ := new(big.Int).SetString(r, 10)
		if inputs[i].Cmp(v) != -1 {
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

func parseProofData(pr verifiable.ProofData) (proofPairingData, error) {
	var (
		p   proofPairingData
		err error
	)

	p.A, err = stringToG1(pr.A)
	if err != nil {
		return p, err
	}

	p.B, err = stringToG2(pr.B)
	if err != nil {
		return p, err
	}

	p.C, err = stringToG1(pr.C)
	if err != nil {
		return p, err
	}

	return p, err
}

func parseVK(vkStr vkJSON) (*vk, error) {
	var v vk
	var err error
	v.Alpha, err = stringToG1(vkStr.Alpha)
	if err != nil {
		return nil, err
	}

	v.Beta, err = stringToG2(vkStr.Beta)
	if err != nil {
		return nil, err
	}

	v.Gamma, err = stringToG2(vkStr.Gamma)
	if err != nil {
		return nil, err
	}

	v.Delta, err = stringToG2(vkStr.Delta)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(vkStr.IC); i++ {
		p, err := stringToG1(vkStr.IC[i])
		if err != nil {
			return nil, err
		}
		v.IC = append(v.IC, p)
	}

	return &v, nil
}
