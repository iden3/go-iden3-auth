package types

import (
	"math/big"
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
	AuthData       *AuthenticationMetadata
	AdditionalData map[string]interface{}
}

// ZeroKnowledgeProof represents structure of zkp object
type ZeroKnowledgeProof struct {
	Type        ProofType `json:"type"`
	CircuitID   CircuitID `json:"circuit_id"`
	PubSignals  []*big.Int
	ProofData   *ProofData
	CircuitData *CircuitData
	ProofMetadata
	TypedScope
}

// AuthenticationMetadata defines basic metadata that can be retrieved from auth proof
type AuthenticationMetadata struct {
	UserIdentifier          string
	AuthenticationChallenge string
}

// ProofData describes three components of zkp proof
type ProofData struct {
	A string `json:"pi_a"`
	B string `json:"pi_b"`
	C string `json:"pi_c"`
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

// AuthenticationRules represents structure rules for zkp authentication  proof
type AuthenticationRules struct {
	Challenge int    `json:"challenge"`
	Audience  string `json:"audience"`
}

// ZeroKnowledgeProofRequest represents structure for request of zkp proof
type ZeroKnowledgeProofRequest struct {
	CircuitID  CircuitID              `json:"circuit_id,omitempty"`
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
	TypedScope
}
