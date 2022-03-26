// The models package defines internal structs that uses for validate/generate proof.

package models

import (
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// R is the mod of the finite field
var R, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// ProofData describes three components of zkp proof in bn256 format.
type ProofData struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
}

// Vk is the Verification Key data structure in bn256 format.
type Vk struct {
	Alpha *bn256.G1
	Beta  *bn256.G2
	Gamma *bn256.G2
	Delta *bn256.G2
	IC    []*bn256.G1
}
