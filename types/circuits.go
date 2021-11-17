package types

// CircuitID is a type that must be used for circuit id definition
type CircuitID string

const (
	// AuthCircuitID is a type that must be used for auth circuit id definition
	AuthCircuitID CircuitID = "auth"
	// KycBySignaturesCircuitID is a type that must be used for kycBySignatures circuit id definition
	KycBySignaturesCircuitID CircuitID = "kycBySignatures"
	// KycCircuitCircuitID is a type that must be used for kyc circuit id definition
	KycCircuitCircuitID CircuitID = "kyc"
)

// CircuitData represents data that describes circuit
type CircuitData struct {
	ID              CircuitID
	Description     string
	VerificationKey VerificationKeyJSON
	Metadata        string
}
