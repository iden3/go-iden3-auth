package pubsignals

import (
	"reflect"
	"sync"

	"github.com/iden3/go-circuits/v2"
	"github.com/pkg/errors"
)

var signalsVerifierRegistry = map[circuits.CircuitID]reflect.Type{}
var circuitsLock = new(sync.RWMutex)

var (
	// ErrGlobalStateIsNotValid invalid global state id.
	ErrGlobalStateIsNotValid = errors.New("global state is not valid")
	// ErrIssuerClaimStateIsNotValid declares that issuer state is invalid.
	ErrIssuerClaimStateIsNotValid = errors.New("issuer state is not valid")
	// ErrIssuerNonRevocationClaimStateIsNotValid declares that issuer non-revocation state is invalid.
	ErrIssuerNonRevocationClaimStateIsNotValid = errors.New("issuer state for non-revocation proofs is not valid")
	// ErrProofGenerationOutdated declares that generated proof is outdated.
	ErrProofGenerationOutdated = errors.New("generated proof is outdated")
	// ErrWronProofType declares that query proof type doesn't match circuit proof type
	ErrWronProofType = errors.New("invalid proof type")
)

const (
	linkedMultiQuery3                = "linkedMultiQuery3"
	linkedMultiQuery5                = "linkedMultiQuery5"
	credentialAtomicQueryV3_16_16_64 = "credentialAtomicQueryV3-16-16-64" // #nosec G101 -- this is a circuit ID, not a credential
)

// RegisterVerifier is factory for public signals init.
// This is done during init() in the method's implementation
func RegisterVerifier(id circuits.CircuitID, t reflect.Type) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()

	signalsVerifierRegistry[id] = t
}

// nolint // register supported circuit
func init() {
	RegisterVerifier(circuits.AuthV2CircuitID, reflect.TypeOf(AuthV2{}))
	RegisterVerifier(circuits.AuthV3CircuitID, reflect.TypeOf(AuthV3{}))
	RegisterVerifier(circuits.AuthV3_8_32CircuitID, reflect.TypeOf(AuthV3{}))
	RegisterVerifier(circuits.AtomicQuerySigV2CircuitID, reflect.TypeOf(AtomicQuerySigV2{}))
	RegisterVerifier(circuits.AtomicQueryMTPV2CircuitID, reflect.TypeOf(AtomicQueryMTPV2{}))
	RegisterVerifier(circuits.AtomicQueryV3CircuitID, reflect.TypeOf(AtomicQueryV3{}))
	RegisterVerifier(circuits.LinkedMultiQuery10CircuitID, reflect.TypeOf(LinkedMultiQuery{}))
	RegisterVerifier(circuits.AtomicQueryV3StableCircuitID, reflect.TypeOf(AtomicQueryV3{}))
	RegisterVerifier(circuits.CircuitID(credentialAtomicQueryV3_16_16_64), reflect.TypeOf(AtomicQueryV3{}))
	RegisterVerifier(circuits.LinkedMultiQueryStableCircuitID, reflect.TypeOf(LinkedMultiQuery{}))
	RegisterVerifier(circuits.CircuitID(linkedMultiQuery3), reflect.TypeOf(LinkedMultiQuery{}))
	RegisterVerifier(circuits.CircuitID(linkedMultiQuery5), reflect.TypeOf(LinkedMultiQuery{}))

}

// GetVerifier return specific public signals verifier
func GetVerifier(id circuits.CircuitID) (Verifier, error) {
	verifierType, ok := signalsVerifierRegistry[id]
	if !ok {
		return nil, errors.New("public signals verifier for circuit is not registered")
	}

	v := reflect.New(verifierType).Interface().(Verifier)

	// per-circuit parameter injection
	if s, ok := v.(QueryLengthSetter); ok {
		switch id {
		case circuits.LinkedMultiQueryStableCircuitID:
			s.SetQueryLength(10)
		case circuits.CircuitID(linkedMultiQuery3):
			s.SetQueryLength(3)
		case circuits.CircuitID(linkedMultiQuery5):
			s.SetQueryLength(5)
		}
	}

	if bc, ok := v.(BaseConfigSetter); ok {
		if id == circuits.CircuitID(credentialAtomicQueryV3_16_16_64) {
			bc.SetBaseConfig(circuits.BaseConfig{
				MTLevel:        16,
				MTLevelClaim:   16,
				ValueArraySize: 64,
				MTLevelOnChain: 0,
			})
		}
	}

	return v, nil
}
