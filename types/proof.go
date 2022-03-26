// The types package defines the format of communication between the library and the end user.

package types

import (
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/internal/models"
)

// ProofType is a type that must be used for proof definition
type ProofType string

func (p ProofType) String() string {
	return string(p)
}

var (
	// ZeroKnowledgeProofType describes zkp type
	ZeroKnowledgeProofType ProofType = "zeroknowledge"
	// SignatureProofType describes signature
	SignatureProofType ProofType = "signature"
)

// ProofMetadata defines basic metadata that can be retrieved from any proof
type ProofMetadata struct {
	AuthData       *AuthenticationMetadata `json:"auth_data,omitempty"`
	AdditionalData map[string]interface{}  `json:"additional_data,omitempty"`
}

// ZeroKnowledgeProof represents structure of zkp object
type ZeroKnowledgeProof struct {
	Type        ProofType          `json:"type"`
	CircuitID   circuits.CircuitID `json:"circuit_id"`
	PubSignals  []string           `json:"pub_signals"`
	ProofData   *ProofData         `json:"proof_data"`
	CircuitData *CircuitData       `json:"circuit_data,omitempty"`
	ProofMetadata
	TypedScope `json:"-"`
}

// AuthenticationMetadata defines basic metadata that can be retrieved from auth proof
type AuthenticationMetadata struct {
	UserIdentifier          string
	UserState               string
	AuthenticationChallenge string
}

// ProofData describes three components of zkp proof
type ProofData struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

func (pr *ProofData) ToInternalProofData() (models.ProofData, error) {
	var (
		p   models.ProofData
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

// VerificationKeyJSON describes type verification key in JSON format
type VerificationKeyJSON string

// SignatureProof represents structure of signature proof object
type SignatureProof struct {
	Type      ProofType `json:"type"`
	KeyType   string    `json:"key_type"`
	Signature string    `json:"signature"`
	Challenge string    `json:"challenge"`
	ProofMetadata
	TypedScope `json:"-"`
}

// KYCBySignatureRules represents structure rules zkp kycBySignatures proof
type KYCBySignatureRules struct {
	Challenge        int      `json:"challenge"`
	CountryBlacklist []int    `json:"countryBlacklist"`
	CurrentYear      int      `json:"currentYear"`
	CurrentMonth     int      `json:"currentMonth"`
	CurrentDay       int      `json:"currentDay"`
	MinAge           int      `json:"minAge"`
	Audience         string   `json:"audience"`
	AllowedIssuers   []string `json:"allowedIssuers"`
}

// ZeroKnowledgeProofRequest represents structure for request of zkp proof
type ZeroKnowledgeProofRequest struct {
	CircuitID  circuits.CircuitID     `json:"circuit_id,omitempty"`
	Type       ProofType              `json:"type"`
	Rules      map[string]interface{} `json:"rules,omitempty"`
	TypedScope `json:"-"`
}

// SignatureProofRequest represents	 structure for request of signature proof
type SignatureProofRequest struct {
	Rules   map[string]interface{} `json:"rules,omitempty"`
	KeyType string                 `json:"keyType,omitempty"`
	Format  string                 `json:"format,omitempty"`
	Message int                    `json:"message,omitempty"`
	Type    ProofType              `json:"type"`
	TypedScope
}

// VkString is the Verification Key data structure in string format (from json).
type VkString struct {
	Alpha []string   `json:"vk_alpha_1"`
	Beta  [][]string `json:"vk_beta_2"`
	Gamma [][]string `json:"vk_gamma_2"`
	Delta [][]string `json:"vk_delta_2"`
	IC    [][]string `json:"IC"`
}

func (vk *VkString) ToInternalVk() (*models.Vk, error) {
	var v models.Vk
	var err error
	v.Alpha, err = stringToG1(vk.Alpha)
	if err != nil {
		return nil, err
	}

	v.Beta, err = stringToG2(vk.Beta)
	if err != nil {
		return nil, err
	}

	v.Gamma, err = stringToG2(vk.Gamma)
	if err != nil {
		return nil, err
	}

	v.Delta, err = stringToG2(vk.Delta)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(vk.IC); i++ {
		p, err := stringToG1(vk.IC[i])
		if err != nil {
			return nil, err
		}
		v.IC = append(v.IC, p)
	}

	return &v, nil
}

type PublicInputs []string

func (pi PublicInputs) ToBigInt() ([]*big.Int, error) {
	var public []*big.Int
	for _, s := range pi {
		sb, err := stringToBigInt(s)
		if err != nil {
			return nil, err
		}
		public = append(public, sb)
	}
	return public, nil
}
