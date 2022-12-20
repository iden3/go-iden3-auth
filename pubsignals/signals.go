package pubsignals

import (
	"reflect"
	"sync"

	"github.com/iden3/go-circuits"
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
	RegisterVerifier(circuits.AtomicQuerySigV2CircuitID, reflect.TypeOf(AtomicQuerySigV2{}))
	RegisterVerifier(circuits.AtomicQueryMTPV2CircuitID, reflect.TypeOf(AtomicQueryMTPV2{}))
}

// GetVerifier return specific public signals verifier
func GetVerifier(id circuits.CircuitID) (Verifier, error) {
	verifierType, ok := signalsVerifierRegistry[id]
	if !ok {
		return nil, errors.New("public signals verifier for circuit is not registered")
	}

	return reflect.New(verifierType).Interface().(Verifier), nil
}
