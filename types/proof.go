package types

import "github.com/iden3/go-circuits"

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
